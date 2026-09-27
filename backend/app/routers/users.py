"""Admin-only user provisioning (the enterprise alternative to self-signup)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import ROLE_CAPABILITIES, ROLE_LABELS, get_current_user, record_audit, require_admin
from ..models import AuditLog, Incident, User
from ..schemas import AuditOut, UserCreate, UserOut, UserUpdate
from ..security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut], summary="List provisioned users")
def list_users(
    q: str | None = Query(default=None, description="Substring match on name or email"),
    role: str | None = None,
    include_inactive: bool = True,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[User]:
    stmt = select(User).order_by(User.created_at)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            func.lower(User.full_name).like(like) | func.lower(User.email).like(like)
        )
    if role:
        stmt = stmt.where(User.role == role)
    if not include_inactive:
        stmt = stmt.where(User.is_active.is_(True))
    return list(db.execute(stmt).scalars().all())


@router.get("/roles", summary="Role catalogue and capability matrix")
def roles() -> dict:
    return {
        "roles": [
            {
                "key": key,
                "label": ROLE_LABELS[key],
                "capabilities": caps,
                "capability_count": len(caps),
            }
            for key, caps in ROLE_CAPABILITIES.items()
        ],
        "all_capabilities": sorted({c for caps in ROLE_CAPABILITIES.values() for c in caps}),
    }


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED,
             summary="Provision a user (admin only)")
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    email = payload.email.lower().strip()
    exists = db.execute(select(User).where(func.lower(User.email) == email)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail=f"{email} is already provisioned.")

    user = User(
        email=email, full_name=payload.full_name.strip(), role=payload.role,
        job_title=payload.job_title, team=payload.team, is_active=payload.is_active,
        hashed_password=hash_password(payload.password), auth_provider="local",
    )
    db.add(user)
    db.flush()
    record_audit(db, actor=admin, action="user.create", target_type="user",
                 target_id=user.id, detail=f"role={user.role}", request=request)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut, summary="Update a user (admin only)")
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    changes = []
    if payload.role and payload.role != user.role:
        if user.id == admin.id and payload.role != "admin":
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own administrator role — ask another admin.",
            )
        if user.role == "admin" and payload.role != "admin":
            remaining = db.execute(
                select(func.count()).select_from(User).where(
                    User.role == "admin", User.is_active.is_(True), User.id != user.id
                )
            ).scalar_one()
            if remaining == 0:
                raise HTTPException(
                    status_code=400,
                    detail="At least one active administrator must remain.",
                )
        changes.append(f"role {user.role}→{payload.role}")
        user.role = payload.role

    for field in ("full_name", "job_title", "team"):
        value = getattr(payload, field)
        if value is not None and value != getattr(user, field):
            changes.append(f"{field} changed")
            setattr(user, field, value)

    if payload.is_active is not None and payload.is_active != user.is_active:
        if user.id == admin.id and not payload.is_active:
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")
        changes.append("activated" if payload.is_active else "deactivated")
        user.is_active = payload.is_active

    if payload.password:
        user.hashed_password = hash_password(payload.password)
        user.failed_logins = 0
        changes.append("password reset")

    record_audit(db, actor=admin, action="user.update", target_type="user",
                 target_id=user.id, detail="; ".join(changes) or "no changes", request=request)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", summary="Deactivate a user (admin only)")
def deactivate_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")

    # Accounts are never hard-deleted: incident assignment history and the audit
    # trail must remain attributable.
    user.is_active = False
    open_cases = db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.assignee_id == user.id,
            Incident.status.notin_(["closed", "false_positive"]),
        )
    ).scalar_one()
    record_audit(db, actor=admin, action="user.deactivate", target_type="user",
                 target_id=user.id, detail=f"{open_cases} open case(s) still assigned",
                 request=request)
    db.commit()
    return {
        "detail": f"{user.email} deactivated.",
        "open_cases_still_assigned": open_cases,
        "note": "Accounts are deactivated rather than deleted to preserve the audit trail.",
    }


@router.get("/audit", response_model=list[AuditOut], summary="Audit log (admin only)")
def audit_log(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = None,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    return list(db.execute(stmt).scalars().all())
