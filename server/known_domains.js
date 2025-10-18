// known_domains.js
// Structured "ground truth" database for phishing detection.
// - Each company maps to an array of official domains and common legit subdomains
// - All keys (keywords) are lowercase
// - Use helper functions below for normalization and lookups

// NOTE: This is a non-exhaustive, evolving list. Use it as a base and expand as you discover new legit subdomains
// or region-specific portals. Treat entries here as authoritative positives for allowlisting/verification.

const TECH = {
  'google': [
    'google.com',
    'accounts.google.com',
    'myaccount.google.com',
    'mail.google.com',
    'console.cloud.google.com',
    'play.google.com',
    'payments.google.com',
    'support.google.com'
  ],
  'microsoft': [
    'microsoft.com',
    'account.microsoft.com',
    'login.microsoftonline.com',
    'office.com',
    'outlook.com',
    'portal.azure.com',
    'onedrive.live.com',
    'support.microsoft.com'
  ],
  'apple': [
    'apple.com',
    'appleid.apple.com',
    'icloud.com',
    'developer.apple.com',
    'itunes.apple.com',
    'support.apple.com'
  ],
  'facebook': [
    'facebook.com',
    'm.facebook.com',
    'business.facebook.com',
    'developers.facebook.com',
    'help.facebook.com'
  ],
  'instagram': ['instagram.com', 'help.instagram.com'],
  'meta': ['meta.com', 'about.meta.com'],
  'twitter': ['twitter.com', 'x.com', 'ads.twitter.com'],
  'openai': ['openai.com', 'chat.openai.com', 'platform.openai.com'],
  'github': ['github.com', 'gist.github.com', 'github.io', 'pages.github.com'],
  'gitlab': ['gitlab.com', 'about.gitlab.com'],
  'bitbucket': ['bitbucket.org', 'atlassian.com'],
  'slack': ['slack.com', 'api.slack.com', 'slack-edge.com'],
  'zoom': ['zoom.us', 'zoom.com', 'marketplace.zoom.us'],
  'dropbox': ['dropbox.com', 'paper.dropbox.com'],
  'adobe': ['adobe.com', 'accounts.adobe.com', 'experienceleague.adobe.com'],
  'figma': ['figma.com', 'www.figma.com'],
  'notion': ['notion.so', 'www.notion.so'],
  'canva': ['canva.com', 'www.canva.com'],
  'aws': ['amazonaws.com', 'aws.amazon.com', 'console.aws.amazon.com', 'signin.aws.amazon.com'],
  'azure': ['azure.com', 'portal.azure.com', 'management.azure.com'],
  'heroku': ['heroku.com', 'dashboard.heroku.com'],
  'digitalocean': ['digitalocean.com', 'cloud.digitalocean.com'],
  'oracle cloud': ['oracle.com', 'cloud.oracle.com'],
  'cloudflare': ['cloudflare.com', 'dash.cloudflare.com', 'workers.dev'],
  'fastly': ['fastly.com'],
  'vercel': ['vercel.com', 'vercel.app'],
  'netlify': ['netlify.com', 'app.netlify.com']
};

const FINANCE = {
  'bank of america': ['bankofamerica.com', 'secure.bankofamerica.com'],
  'chase': ['chase.com', 'secure01.chase.com'],
  'wells fargo': ['wellsfargo.com', 'online.wellsfargo.com'],
  'citibank': ['citibank.com', 'online.citibank.com'],
  'hsbc': ['hsbc.com', 'my.hsbc'],
  'paypal': ['paypal.com', 'www.paypal.com', 'signin.paypal.com'],
  'stripe': ['stripe.com', 'dashboard.stripe.com', 'connect.stripe.com'],
  'square': ['squareup.com', 'square.com'],
  'american express': ['americanexpress.com', 'account.americanexpress.com'],
  'visa': ['visa.com'],
  'mastercard': ['mastercard.com'],
  'paypal-sandbox': ['sandbox.paypal.com'],
  'paytm': ['paytm.com', 'secure.paytm.in'],
  'phonepe': ['phonepe.com'],
  'google pay': ['pay.google.com', 'pay.google.com'],
  'apple pay': ['apple.com', 'apple.com/apple-pay'],
  'wise': ['wise.com', 'transferwise.com'],
  'revolut': ['revolut.com']
};

const BANKS_IN = {
  'state bank of india': ['sbi.co.in', 'onlinesbi.sbi'],
  'hdfc bank': ['hdfcbank.com'],
  'icici bank': ['icicibank.com'],
  'axis bank': ['axisbank.com'],
  'kotak mahindra bank': ['kotak.com'],
  'central bank of india': ['centralbankofindia.co.in'],
  'bank of baroda': ['bankofbaroda.in'],
  'yes bank': ['yesbank.in'],
  'idbi': ['idbi.com'],
  'indian overseas bank': ['iob.in']
};

const ECOMMERCE = {
  'amazon': ['amazon.com', 'amazon.in', 'sellercentral.amazon.com', 'payments.amazon.com'],
  'ebay': ['ebay.com'],
  'shopify': ['shopify.com', 'checkout.shopify.com'],
  'flipkart': ['flipkart.com'],
  'myntra': ['myntra.com'],
  'etsy': ['etsy.com'],
  'alibaba': ['alibaba.com', 'aliexpress.com'],
  'taobao': ['taobao.com'],
  'nykaa': ['nykaa.com'],
  'meesho': ['meesho.com'],
  'walmart': ['walmart.com']
};

const LOGISTICS = {
  'fedex': ['fedex.com', 'fedex.com/en-us/tracking'],
  'ups': ['ups.com'],
  'dhl': ['dhl.com'],
  'usps': ['usps.com'],
  'bluedart': ['bluedart.com'],
  'delhivery': ['delhivery.com']
};

const TELECOM = {
  'airtel': ['airtel.in', 'www.airtel.in'],
  'jio': ['jio.com', 'my.jio.com'],
  'vodafone': ['vodafone.com', 'vodafoneidea.com'],
  'verizon': ['verizon.com'],
  'att': ['att.com']
};

const GOVERNMENT = {
  'uidai': ['uidai.gov.in', 'resident.uidai.gov.in'],
  'irs': ['irs.gov'],
  'gov.uk': ['gov.uk'],
  'usa gov': ['usa.gov'],
  'income tax india': ['incometax.gov.in'],
  'irctc': ['irctc.co.in'],
  'india post': ['indiapost.gov.in'],
  'passport office india': ['passportindia.gov.in']
};

const ENTERPRISE_SAAS = {
  'salesforce': ['salesforce.com', 'login.salesforce.com', 'help.salesforce.com'],
  'sap': ['sap.com'],
  'workday': ['workday.com'],
  'service now': ['servicenow.com', 'service-now.com'],
  'zendesk': ['zendesk.com', 'support.zendesk.com'],
  'asana': ['asana.com'],
  'trello': ['trello.com'],
  'zoominfo': ['zoominfo.com'],
  'hubspot': ['hubspot.com', 'app.hubspot.com']
};

const SECURITY = {
  'cloudflare': ['cloudflare.com', 'dash.cloudflare.com'],
  'okta': ['okta.com', 'developer.okta.com', 'login.okta.com'],
  'auth0': ['auth0.com', 'manage.auth0.com'],
  'lastpass': ['lastpass.com', 'vault.lastpass.com'],
  '1password': ['1password.com', 'my.1password.com'],
  'duo': ['duo.com', 'duo.com/login'],
  'crowdstrike': ['crowdstrike.com'],
  'microsoft defender': ['microsoft.com/security']
};

const DEV_PLATFORMS = {
  'npm': ['npmjs.com'],
  'pypi': ['pypi.org'],
  'maven central': ['search.maven.org'],
  'docker hub': ['hub.docker.com'],
  'bitbucket': ['bitbucket.org'],
  'stack overflow': ['stackoverflow.com'],
  'stackoverflow jobs': ['stackoverflow.com/jobs'],
  'npmjs': ['npmjs.com']
};

const SOCIAL_STREAMING = {
  'youtube': ['youtube.com', 'studio.youtube.com', 'support.google.com/youtube'],
  'netflix': ['netflix.com'],
  'hulu': ['hulu.com'],
  'disney plus': ['disneyplus.com'],
  'prime video': ['primevideo.com'],
  'spotify': ['spotify.com'],
  'soundcloud': ['soundcloud.com'],
  'tiktok': ['tiktok.com']
};

const EDUCATION = {
  'coursera': ['coursera.org'],
  'udemy': ['udemy.com'],
  'edx': ['edx.org'],
  'khan academy': ['khanacademy.org'],
  'byjus': ['byjus.com'],
  'unacademy': ['unacademy.com']
};

const HEALTH = {
  'cdc': ['cdc.gov'],
  'who': ['who.int'],
  'nhs': ['nhs.uk'],
  'practo': ['practo.com']
};

const CRYPTO = {
  'coinbase': ['coinbase.com', 'pro.coinbase.com'],
  'binance': ['binance.com', 'accounts.binance.com'],
  'kraken': ['kraken.com'],
  'ftx': ['ftx.com'],
  'coinmarketcap': ['coinmarketcap.com']
};

const JOBS = {
  'linkedin': ['linkedin.com', 'www.linkedin.com'],
  'indeed': ['indeed.com'],
  'glassdoor': ['glassdoor.com']
};

const NEWS = {
  'nytimes': ['nytimes.com'],
  'bbc': ['bbc.co.uk', 'bbc.com'],
  'the guardian': ['theguardian.com'],
  'reuters': ['reuters.com']
};

const OTHERS = {
  'uber': ['uber.com', 'auth.uber.com'],
  'ola': ['olacabs.com'],
  'zomato': ['zomato.com'],
  'swiggy': ['swiggy.com'],
  'paypal': ['paypal.com'],
  'google workspace': ['workspace.google.com']
};

const TRAVEL = {
  // =========================
  // Online Travel Agencies (OTAs) / Booking platforms
  // =========================
  'booking.com': ['booking.com', 'account.booking.com', 'admin.booking.com'],
  'expedia': ['expedia.com', 'www.expedia.com', 'accounts.expedia.com', 'expediapartnercentral.com'],
  'agoda': ['agoda.com', 'secure.agoda.com', 'partners.agoda.com'],
  'priceline': ['priceline.com'],
  'kayak': ['kayak.com'],
  'skyscanner': ['skyscanner.com'],
  'trivago': ['trivago.com'],
  'hotels.com': ['hotels.com', 'secure.hotels.com'],
  'orbitz': ['orbitz.com'],
  'travelocity': ['travelocity.com'],
  'cleartrip': ['cleartrip.com', 'www.cleartrip.com'],
  'makemytrip': ['makemytrip.com', 'accounts.makemytrip.com', 'login.makemytrip.com'],
  'yatra': ['yatra.com'],
  'goibibo': ['goibibo.com'],
  'tripadvisor': ['tripadvisor.com', 'www.tripadvisor.com'],
  'tripexpert': ['tripexpert.com'],
  'hostelworld': ['hostelworld.com'],
  'lastminute': ['lastminute.com'],
  'holidayiq': ['holidayiq.com'],

  // =========================
  // Global Hotel Chains
  // =========================
  'marriott': [
    'marriott.com',
    'marriottbonvoy.com',
    'accounts.marriott.com',
    'secure.marriott.com',
    'reservations.marriott.com'
  ],
  'hilton': [
    'hilton.com',
    'hiltonhonors.com',
    'secure.hilton.com',
    'hhonors.hilton.com'
  ],
  'hyatt': [
    'hyatt.com',
    'hyattregency.hyatt.com',
    'accounts.hyatt.com',
    'world.hyatt.com'
  ],
  'ihg': [
    'ihg.com',
    'ihg.com/reservation',
    'clubihg.com',
    'myihg.com'
  ],
  'accor': [
    'accor.com',
    'accorhotels.com',
    'all.accor.com' // ALL - Accor Live Limitless
  ],
  'wyndham': ['wyndhamhotels.com', 'wyndhamrewards.com'],
  'best western': ['bestwestern.com', 'bw.com'],
  'choice hotels': ['choicehotels.com'],
  'radisson': ['radissonhotels.com', 'radisson.com'],
  'shangri-la': ['shangri-la.com', 'shangri-la.com/myaccount'],
  'taj hotels': ['tajhotels.com', 'tajhotels.com/en-in', 'tajhotels.com/loyalty'],
  'oberoi hotels': ['oberoihotels.com'],
  'le meridien': ['lemeridien.com'],
  'ritz carlton': ['ritzcarlton.com', 'theritzcarlton.com'],

  // =========================
  // Boutique hotel groups / regional hotel brands
  // =========================
  'oceanic chains': ['belmond.com', 'aman.com'], // examples
  'taj': ['tajhotels.com'],
  'itc hotels': ['itchotels.in', 'itchotels.in/offers'],
  'luxury collections': ['luxurycollection.com'],

  // =========================
  // Airlines (major/global carriers) - include common booking/check-in/account domains
  // =========================
  'american airlines': ['aa.com', 'americanairlines.com'],
  'delta': ['delta.com'],
  'united': ['united.com'],
  'british airways': ['britishairways.com', 'ba.com'],
  'lufthansa': ['lufthansa.com'],
  'air france': ['airfrance.com'],
  'klm': ['klm.com'],
  'qatar airways': ['qatarairways.com'],
  'emirates': ['emirates.com', 'login.emirates.com'],
  'etihad': ['etihad.com'],
  'singapore airlines': ['singaporeair.com'],
  'qantas': ['qantas.com'],
  'air india': ['airindia.in', 'airindia.com'],
  'indigo': ['goindigo.in'],
  'spicejet': ['spicejet.com'],
  'vistara': ['airvistara.com'],
  'southwest': ['southwest.com'],
  'aeroflot': ['aeroflot.ru'],
  'ana': ['ana.co.jp'],
  'japan airlines': ['jal.co.jp'],

  // =========================
  // Low-cost carriers & regionals
  // =========================
  'ryanair': ['ryanair.com'],
  'easyjet': ['easyjet.com'],
  'airasia': ['airasia.com'],

  // =========================
  // Car Rentals
  // =========================
  'avis': ['avis.com', 'www.avis.com'],
  'hertz': ['hertz.com'],
  'enterprise': ['enterprise.com', 'enterprise.co.uk'],
  'budget': ['budget.com'],
  'sixt': ['sixt.com'],
  'payless': ['paylesscar.com'],
  'ola': ['olacabs.com', 'ola.cabs'],
  'uber': ['uber.com', 'm.uber.com'],

  // =========================
  // Cruise Lines
  // =========================
  'carnival': ['carnival.com'],
  'royal caribbean': ['royalcaribbean.com'],
  'norwegian': ['ncl.com', 'norwegiancruiseline.com'],
  'msc cruises': ['msccruises.com'],
  'princess cruises': ['princess.com'],

  // =========================
  // Trains (selected national operators & booking portals)
  // =========================
  'irctc': ['irctc.co.in', 'www.irctc.co.in'],
  'amtrak': ['amtrak.com'],
  'eurail': ['eurail.com'],
  'national rail uk': ['nationalrail.co.uk'],
  'sbb': ['sbb.ch'],

  // =========================
  // Bus / Coach operators & booking apps
  // =========================
  'greyhound': ['greyhound.com'],
  'redbus': ['redbus.in'],
  'megabus': ['megabus.com'],
  'redbus global': ['redbus.in', 'redbus.co.uk'],

  // =========================
  // Airports & Airport Authority portals (selected)
  // =========================
  'chhatrapati shivaji maharaj international airport': ['csmiaaerialtrams.com'], // example placeholder; include official airports when known
  'delhi airport': ['aai.aero', 'delhiairport.nic.in', 'indira gandhi international airport'], // note: normalize to hostnames in code
  'heathrow': ['heathrow.com'],
  'jfk airport': ['jfkiat.com', 'jfkairport.com'],
  'schiphol': ['schiphol.nl'],

  // =========================
  // Travel Insurance Providers
  // =========================
  'allianz travel insurance': ['allianztravelinsurance.com', 'allianz.com'],
  'axa travel insurance': ['axa.com'],
  'bupa': ['bupa.com'],

  // =========================
  // Ancillary & Travel Services (carriers, lounge, visa)
  // =========================
  'visa processing': ['vfsglobal.com', 'vfsglobal.co.uk', 'vfsvisaonline.com'],
  'skyscanner partners': ['partners.skyscanner.net'],
  'travelport': ['travelport.com'],
  'sabreu': ['sabre.com', 'sabreairlinesolutions.com'],
  'amadeus': ['amadeus.com'],

  // =========================
  // Regional & Specialty OTAs / Travel Apps (India + global examples)
  // =========================
  'makemytrip': ['makemytrip.com'],
  'cleartrip': ['cleartrip.com'],
  'yatra': ['yatra.com'],
  'ixigo': ['ixigo.com'],
  'holidayiq': ['holidayiq.com'],
  'musafir': ['musafir.com'],

  // =========================
  // Misc: loyalty / rewards subdomains commonly used
  // =========================
  'marriott bonvoy': ['marriottbonvoy.marriott.com', 'marriott.com/loyalty'],
  'hilton honors': ['hiltonhonors.hilton.com', 'hiltonhonors.com'],
  'accor all': ['all.accor.com'],

  // Add more hotels, airlines, regional OTAs, train operators, and airports as needed
};

// ------------------------------
// Merge travel into industries and into flattened maps
// ------------------------------
const industries = {
  tech: TECH,
  finance: FINANCE,
  banks_in: BANKS_IN,
  ecommerce: ECOMMERCE,
  logistics: LOGISTICS,
  telecom: TELECOM,
  government: GOVERNMENT,
  enterprise_saas: ENTERPRISE_SAAS,
  security: SECURITY,
  dev: DEV_PLATFORMS,
  social_streaming: SOCIAL_STREAMING,
  travel: TRAVEL,           // newly expanded
  education: EDUCATION,
  health: HEALTH,
  crypto: CRYPTO,
  jobs: JOBS,
  news: NEWS,
  others: OTHERS
};

// Build flattened knownDomains and reverse map
const knownDomains = {};
Object.keys(industries).forEach(group => {
  const obj = industries[group] || {};
  Object.keys(obj).forEach(key => {
    const k = key.toLowerCase();
    knownDomains[k] = Array.from(new Set((knownDomains[k] || []).concat(obj[key])));
  });
});

const domainToKeywords = {};
Object.keys(knownDomains).forEach(keyword => {
  knownDomains[keyword].forEach(domain => {
    const d = domain.toLowerCase().replace(/^www\./, '');
    domainToKeywords[d] = domainToKeywords[d] || [];
    if (!domainToKeywords[d].includes(keyword)) domainToKeywords[d].push(keyword);
  });
});

function _normalizeHost(input) {
  if (!input) return '';
  let host = input.toString().trim().toLowerCase();
  try {
    if (host.indexOf('http://') === 0 || host.indexOf('https://') === 0) {
      host = new URL(host).hostname;
    }
  } catch (e) {}
  host = host.split(':')[0];
  if (host.startsWith('www.')) host = host.slice(4);
  return host;
}

function isKnownDomain(input) {
  const host = _normalizeHost(input);
  if (!host) return false;
  if (domainToKeywords[host]) return true;
  for (const knownDomain of Object.keys(domainToKeywords)) {
    if (host === knownDomain) return true;
    if (host.endsWith('.' + knownDomain)) return true;
  }
  return false;
}

function getDomainsForKeyword(keyword) {
  if (!keyword) return [];
  const k = keyword.toLowerCase();
  return knownDomains[k] ? [...knownDomains[k]] : [];
}

function findKeywordForDomain(input) {
  const host = _normalizeHost(input);
  const found = new Set();
  if (!host) return [];
  if (domainToKeywords[host]) domainToKeywords[host].forEach(k => found.add(k));
  Object.keys(domainToKeywords).forEach(knownDomain => {
    if (host === knownDomain || host.endsWith('.' + knownDomain)) {
      domainToKeywords[knownDomain].forEach(k => found.add(k));
    }
  });
  return Array.from(found);
}

module.exports = {
  industries,
  knownDomains,
  domainToKeywords,
  isKnownDomain,
  getDomainsForKeyword,
  findKeywordForDomain
};
