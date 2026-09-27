/**
 * Flat 16px stroke icons. Deliberately geometric and uniform — 1.5px stroke,
 * round caps, 24-unit viewBox — so the navigation reads as instrumentation
 * rather than illustration.
 */

const base = {
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
};

const Icon = ({ size = 16, children, className = '', ...rest }) => (
  <svg width={size} height={size} className={className} {...base} {...rest} aria-hidden="true">
    {children}
  </svg>
);

export const IconGauge = (p) => (
  <Icon {...p}>
    <path d="M3 13a9 9 0 0 1 18 0" />
    <path d="M12 13l4.5-3.5" />
    <circle cx="12" cy="13" r="1.4" />
    <path d="M3 19h18" />
  </Icon>
);

export const IconAlert = (p) => (
  <Icon {...p}>
    <path d="M12 4.5 3.5 19h17L12 4.5Z" />
    <path d="M12 10v4" />
    <path d="M12 16.6v.4" />
  </Icon>
);

export const IconStream = (p) => (
  <Icon {...p}>
    <path d="M3 7h7" />
    <path d="M14 7h7" />
    <path d="M3 12h11" />
    <path d="M18 12h3" />
    <path d="M3 17h5" />
    <path d="M12 17h9" />
    <circle cx="12" cy="7" r="1.6" />
    <circle cx="16" cy="12" r="1.6" />
    <circle cx="10" cy="17" r="1.6" />
  </Icon>
);

export const IconSearch = (p) => (
  <Icon {...p}>
    <circle cx="10.5" cy="10.5" r="6.5" />
    <path d="m15.4 15.4 4.1 4.1" />
  </Icon>
);

export const IconSpark = (p) => (
  <Icon {...p}>
    <path d="M12 3v3.5" />
    <path d="M12 17.5V21" />
    <path d="M3 12h3.5" />
    <path d="M17.5 12H21" />
    <path d="m5.6 5.6 2.5 2.5" />
    <path d="m15.9 15.9 2.5 2.5" />
    <path d="m18.4 5.6-2.5 2.5" />
    <path d="m8.1 15.9-2.5 2.5" />
    <circle cx="12" cy="12" r="2.6" />
  </Icon>
);

export const IconAnomaly = (p) => (
  <Icon {...p}>
    <path d="M3 16.5 7 12l3 3 4-7 3 5 4-3.5" />
    <circle cx="10" cy="15" r="1.2" />
    <circle cx="14" cy="8" r="1.2" />
  </Icon>
);

export const IconShieldCheck = (p) => (
  <Icon {...p}>
    <path d="M12 3.2 5 6v5.5c0 4 2.9 7.6 7 9.3 4.1-1.7 7-5.3 7-9.3V6l-7-2.8Z" />
    <path d="m9 12 2.2 2.2L15.4 10" />
  </Icon>
);

export const IconTrace = (p) => (
  <Icon {...p}>
    <path d="M5 5v14" />
    <rect x="8" y="5.5" width="9" height="3.2" rx="1" />
    <rect x="8" y="10.4" width="12" height="3.2" rx="1" />
    <rect x="8" y="15.3" width="6" height="3.2" rx="1" />
  </Icon>
);

export const IconUsers = (p) => (
  <Icon {...p}>
    <circle cx="9" cy="8" r="3.2" />
    <path d="M3.5 19a5.5 5.5 0 0 1 11 0" />
    <path d="M16 5.4a3.2 3.2 0 0 1 0 5.2" />
    <path d="M17.5 14.2A5.5 5.5 0 0 1 20.5 19" />
  </Icon>
);

export const IconSettings = (p) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="2.8" />
    <path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z" />
  </Icon>
);

export const IconChevron = (p) => (
  <Icon {...p}>
    <path d="m9 6 6 6-6 6" />
  </Icon>
);

export const IconChevronDown = (p) => (
  <Icon {...p}>
    <path d="m6 9 6 6 6-6" />
  </Icon>
);

export const IconCollapse = (p) => (
  <Icon {...p}>
    <rect x="3.5" y="4.5" width="17" height="15" rx="2" />
    <path d="M9.5 4.5v15" />
  </Icon>
);

export const IconSun = (p) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.2 5.2l1.4 1.4M17.4 17.4l1.4 1.4M18.8 5.2l-1.4 1.4M6.6 17.4l-1.4 1.4" />
  </Icon>
);

export const IconMoon = (p) => (
  <Icon {...p}>
    <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z" />
  </Icon>
);

export const IconLock = (p) => (
  <Icon {...p}>
    <rect x="4.5" y="10.5" width="15" height="9.5" rx="2" />
    <path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7" />
  </Icon>
);

export const IconLogout = (p) => (
  <Icon {...p}>
    <path d="M14 5H6.5A1.5 1.5 0 0 0 5 6.5v11A1.5 1.5 0 0 0 6.5 19H14" />
    <path d="m17 8.5 3.5 3.5L17 15.5" />
    <path d="M20 12H10" />
  </Icon>
);

export const IconRefresh = (p) => (
  <Icon {...p}>
    <path d="M20 11.5A8 8 0 0 0 6.2 6.5L4 8.8" />
    <path d="M4 4.5v4.3h4.3" />
    <path d="M4 12.5a8 8 0 0 0 13.8 5l2.2-2.3" />
    <path d="M20 19.5v-4.3h-4.3" />
  </Icon>
);

export const IconDownload = (p) => (
  <Icon {...p}>
    <path d="M12 4v10" />
    <path d="m8 10.5 4 4 4-4" />
    <path d="M4.5 18.5h15" />
  </Icon>
);

export const IconUpload = (p) => (
  <Icon {...p}>
    <path d="M12 15V5" />
    <path d="m8 8.5 4-4 4 4" />
    <path d="M4.5 18.5h15" />
  </Icon>
);

export const IconPlay = (p) => (
  <Icon {...p}>
    <path d="M8 5.5v13l10-6.5-10-6.5Z" />
  </Icon>
);

export const IconCheck = (p) => (
  <Icon {...p}>
    <path d="m5 12.5 4.5 4.5L19 7" />
  </Icon>
);

export const IconClose = (p) => (
  <Icon {...p}>
    <path d="m6 6 12 12M18 6 6 18" />
  </Icon>
);

export const IconPlus = (p) => (
  <Icon {...p}>
    <path d="M12 5v14M5 12h14" />
  </Icon>
);

export const IconFilter = (p) => (
  <Icon {...p}>
    <path d="M4 6h16" />
    <path d="M7 12h10" />
    <path d="M10 18h4" />
  </Icon>
);

export const IconClock = (p) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 7.5V12l3 1.8" />
  </Icon>
);

export const IconGlobe = (p) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M3.5 12h17" />
    <path d="M12 3.5c2.2 2.4 3.4 5.4 3.4 8.5S14.2 18.1 12 20.5C9.8 18.1 8.6 15.1 8.6 12S9.8 5.9 12 3.5Z" />
  </Icon>
);

export const IconServer = (p) => (
  <Icon {...p}>
    <rect x="3.5" y="4.5" width="17" height="6" rx="1.6" />
    <rect x="3.5" y="13.5" width="17" height="6" rx="1.6" />
    <path d="M7 7.5h.01M7 16.5h.01" />
  </Icon>
);

export const IconDoc = (p) => (
  <Icon {...p}>
    <path d="M6 3.5h7l5 5v12H6z" />
    <path d="M13 3.5v5h5" />
    <path d="M9 13h6M9 16.5h4" />
  </Icon>
);

export const IconBook = (p) => (
  <Icon {...p}>
    <path d="M5 4.5h6.5a2.5 2.5 0 0 1 2.5 2.5v12a2 2 0 0 0-2-2H5Z" />
    <path d="M19 4.5h-4.5A2.5 2.5 0 0 0 12 7v12a2 2 0 0 1 2-2h5Z" />
  </Icon>
);

export const IconLink = (p) => (
  <Icon {...p}>
    <path d="M10 13.5a3.5 3.5 0 0 0 5 0l3-3a3.5 3.5 0 0 0-5-5l-1.2 1.2" />
    <path d="M14 10.5a3.5 3.5 0 0 0-5 0l-3 3a3.5 3.5 0 0 0 5 5l1.2-1.2" />
  </Icon>
);

export const IconTarget = (p) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <circle cx="12" cy="12" r="4.5" />
    <circle cx="12" cy="12" r="1" />
  </Icon>
);

export const IconSend = (p) => (
  <Icon {...p}>
    <path d="m4.5 12 15-7-7 15-2-6-6-2Z" />
  </Icon>
);

export const IconMenu = (p) => (
  <Icon {...p}>
    <path d="M4 7h16M4 12h16M4 17h16" />
  </Icon>
);

export const IconArrowUp = (p) => (
  <Icon {...p}>
    <path d="M12 19V5" />
    <path d="m6 11 6-6 6 6" />
  </Icon>
);

export const IconArrowDown = (p) => (
  <Icon {...p}>
    <path d="M12 5v14" />
    <path d="m6 13 6 6 6-6" />
  </Icon>
);
