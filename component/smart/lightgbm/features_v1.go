package lightgbm

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/component/smart"
)

// The 30-slot models were trained with these categorical values and keyword
// lists. Keep this schema frozen: adding two slots in v2 also changed existing
// categories, so truncating a v2 vector would silently misinterpret an old model.
const legacyFeatureSize = 30

func prepareModelFeatures(input *smart.ModelInput, count int) []float64 {
	if count != legacyFeatureSize && count != MaxFeatureSize {
		return nil
	}
	features := prepareFeatures(input)
	if count == MaxFeatureSize {
		return features
	}
	features = features[:legacyFeatureSize]
	features[19] = float64(legacyExtractASNFeature(input.DestIPASN))
	features[20] = float64(legacyExtractGeoIPFeature(input.DestGeoIP))
	address := 0
	if input.Host != "" {
		address = legacyExtractDomainTypeFeature(input.Host)
	} else if input.DestIP != "" {
		address = legacyExtractIPFeature(input.DestIP)
	}
	port := legacyExtractPortFeature(input.DestPort)
	features[21], features[22] = float64(address), float64(port)
	features[25] = float64(legacyDeriveConnectionType(input.DestPort, address, port))
	return features
}

var (
	// common ASN provider categories
	legacyAsnCategories = map[string]int{
		// global tech
		"google":     1,
		"amazon":     2,
		"microsoft":  3,
		"facebook":   4,
		"apple":      5,
		"cloudflare": 6,
		"akamai":     7,
		"fastly":     8,
		"netflix":    9,
		"alibaba":    10,
		"tencent":    11,
		"baidu":      12,
		// china carriers
		"chinatelecom": 13,
		"chinaunicom":  14,
		"chinamobile":  15,
		"chinaedu":     16,
		"cstnet":       17,
		// global CDN and cloud
		"cdn77":        20,
		"limelight":    21,
		"edgecast":     22,
		"stackpath":    23,
		"imperva":      24,
		"oracle":       25,
		"ibm":          26,
		"digitalocean": 27,
		"linode":       28,
		"ovh":          29,
		"hetzner":      30,
		"vultr":        31,
		"cogent":       32,
		"leaseweb":     33,
		"upyun":        34,
		"qingcloud":    35,
		"ucloud":       36,
		// international carriers
		"verizon":  40,
		"comcast":  41,
		"att":      42,
		"sprint":   43,
		"tmobile":  44,
		"level3":   45,
		"ntt":      46,
		"kddi":     47,
		"softbank": 48,
		"telstra":  49,
		"singtel":  50,
		"starhub":  51,
		"m1":       52,
		"pccw":     53,
		"hkbn":     54,
		"smartone": 55,
		"hgc":      56,
		"cht":      57,
		"fetnet":   58,
		"twm":      59,
		// content providers
		"twitter":    70,
		"twitch":     71,
		"discord":    72,
		"spotify":    73,
		"github":     74,
		"steam":      75,
		"blizzard":   76,
		"riotgames":  77,
		"epicgames":  78,
		"ea":         79,
		"bytedance":  80,
		"bilibili":   81,
		"netactuate": 82,
		// internet exchanges
		"hkix":    90,
		"linx":    91,
		"jpix":    92,
		"equinix": 93,
		"sgix":    94,
		"de-cix":  95,
		"ams-ix":  96,
		// education and research
		"cern":     100,
		"mit":      101,
		"stanford": 102,
		"tsinghua": 103,
		"pku":      104,
		// finance
		"visa":       110,
		"mastercard": 111,
		"paypal":     112,
		"stripe":     113,
		"alipay":     114,
		"wechatpay":  115,
	}

	legacyGeoCategories = map[string]int{
		"CN": 1,
		"HK": 2,
		"TW": 3,
		"JP": 4,
		"KR": 5,
		"SG": 6,
		"US": 7,
		"CA": 8,
		"GB": 9,
		"DE": 10,
		"FR": 11,
		"RU": 12,
		"AU": 13,
		"IN": 14,
		"BR": 15,
		"IT": 16,
		"ES": 17,
		"NL": 18,
		"SE": 19,
		"CH": 20,
		"PL": 21,
		"TR": 22,
		"MX": 23,
		"ZA": 24,
		"AR": 25,
		"ID": 26,
		"TH": 27,
		"VN": 28,
		"PH": 29,
		"MY": 30,
		"MO": 31,
	}

	// well known ports
	legacyWellKnownPorts = map[uint16]int{
		22:    1,  // SSH
		25:    2,  // SMTP
		53:    3,  // DNS
		80:    4,  // HTTP
		110:   5,  // POP3
		143:   6,  // IMAP
		443:   7,  // HTTPS
		465:   8,  // SMTPS
		784:   3,  // DNS over QUIC (DoQ)
		853:   3,  // DNS over TLS (DoT)
		993:   9,  // IMAPS
		995:   10, // POP3S
		1194:  11, // OpenVPN
		1812:  12, // RADIUS
		3306:  13, // MySQL
		5053:  3,  // DNS backup port
		5353:  3,  // mDNS
		5355:  3,  // LLMNR
		5432:  14, // PostgreSQL
		6379:  15, // Redis
		8853:  3,  // DoT backup port
		9953:  3,  // DNS management port
		27017: 16, // MongoDB
		6660:  17, // IRC
		6665:  17, // IRC
		6666:  17, // IRC
		6667:  17, // IRC
		6668:  17, // IRC
		6669:  17, // IRC
		8000:  18, // common alternative HTTP port
		8008:  18, // common alternative HTTP port
		8080:  18, // common alternative HTTP port
		8443:  19, // common alternative HTTPS port
		8883:  20, // MQTT over TLS
	}

	// port ranges
	legacyPortRanges = []struct {
		min, max uint16
		category int
	}{
		{0, 1023, 20},      // system ports
		{1024, 49151, 21},  // registered ports
		{49152, 65535, 22}, // dynamic ports
	}

	legacyApiServicePorts = map[uint16]bool{
		8080: true, 8443: true, 9000: true, 9001: true, 9002: true, // common API ports
		3000: true, 3001: true, 5000: true, 5001: true, // development API ports
		8000: true, 8001: true, 8888: true, 4000: true, 4001: true, // other API service ports
		6000: true, 6001: true, 7000: true, 7001: true, // microservice API ports
	}

	legacyDnsServicePorts = map[uint16]bool{
		53:   true, // classic DNS (UDP/TCP)
		853:  true, // DNS over TLS (DoT)
		784:  true, // DNS over QUIC (DoQ), the IANA assigned port
		5053: true, // backup port of some DNS services
		5353: true, // mDNS (Multicast DNS)
		5355: true, // LLMNR (Link-Local Multicast Name Resolution)
		8853: true, // backup port some DoT services use
		9953: true, // management port some DNS services use
	}

	legacyGameSpecificPorts = map[uint16]bool{
		25565: true,                                                                  // Minecraft
		27015: true, 27016: true, 27017: true, 27018: true, 27019: true, 27020: true, // Steam/Counter-Strike
		27031: true, 27036: true, // Steam In-Home Streaming
		3074: true,             // Xbox Live
		3478: true, 3479: true, // PlayStation Network / Nintendo Switch Online
		3659: true,                                                 // Tencent games
		6250: true,                                                 // NetEase games
		7000: true, 7001: true, 7002: true, 7003: true, 7004: true, // various game services
		8393: true, 8394: true, // Origin
		9000: true, 9001: true, // QQ games
		9330: true, 9331: true, // various game services
		9339:  true,                                                                  // various game services
		14000: true, 14001: true, 14002: true, 14003: true, 14004: true, 14008: true, // Battlefield
		16000: true,                                                                  // Battlefield
		18000: true, 18060: true, 18120: true, 18180: true, 18240: true, 18300: true, // Fortnite
		19000: true, 19132: true, // Minecraft PE
		20000: true, 20001: true, 20002: true, // Garena
		22100: true, 22101: true, 22102: true, // Valorant
		30000: true, 30001: true, 30002: true, 30003: true, 30004: true, // Call of Duty
		35000: true, 35001: true, 35002: true, // PUBG / Game for Peace
		40000: true, 40001: true, 40002: true, // various game services
		50000: true, 50001: true, 50002: true, // League of Legends (international)
		50505: true,              // Arena of Valor
		65010: true, 65050: true, // League of Legends: Wild Rift
		3724: true, // World of Warcraft
		6112: true, // Warcraft III/Battle.net
		6881: true, // BitTorrent
	}

	// communication ports
	legacyCommunicationPorts = map[uint16]bool{
		5060: true, 5061: true, // SIP
		1720: true,             // H.323
		1080: true, 1443: true, // proxy and communication services
		3478: true, 3479: true, // STUN/TURN
		5349: true, 5350: true, // STUN/TURN over TLS
		5222: true, 5269: true, // XMPP
		5938: true, // TeamViewer
		6881: true, 6882: true, 6883: true, 6884: true, 6885: true,
		6886: true, 6887: true, 6888: true, 6889: true, // BT
		8801: true, 8802: true, // P2P communication services
		8443:  true,              // common WebRTC / video conference
		10000: true, 10001: true, // WebRTC Media
		19302: true, 19303: true, // Google STUN
		50000: true, 50001: true, 50002: true, // common RTP media ports
		50003: true, 50004: true, 50005: true, // common RTP media ports
		55000: true, 55001: true, // communication applications
		1863:  true, // MSN Messenger
		5228:  true, // Google GCM/FCM
		34784: true, // Zoom
	}

	// game and communication port ranges
	legacyGameCommRanges = []struct {
		min, max uint16
		category int // 1=game, 2=communication, 3=mixed
	}{
		{3000, 3999, 3},   // mixed range of game and communication apps
		{5000, 5999, 2},   // communication applications
		{6000, 7000, 3},   // mixed range of P2P and games
		{8000, 9000, 3},   // mixed range of games and communication
		{10000, 20000, 3}, // mixed range of WebRTC and game services
		{27000, 28000, 1}, // Steam and related game ports
		{30000, 32000, 1}, // common game service ports
		{49000, 50000, 2}, // high ports used by RTP and communication
		{50000, 55000, 3}, // mixed range of communication and games
		{55000, 60000, 2}, // high ports used by communication services
	}

	// streaming and game domain keywords
	legacyStreamingKeywords = []string{
		"youtube", "netflix", "hulu", "spotify", "tiktok", "douyin", "youku", "iqiyi",
		"bilibili", "twitch", "hbo", "disney", "vimeo", "vod", "stream", "video",
		"media", "movie", "tv", "music", "audio", "cdm", "cdn", "content",
		"live", "livestream", "replay", "shorts", "kuaishou", "huya", "douyu",
	}

	legacyGameKeywords = []string{
		"game", "play", "steam", "xbox", "playstation", "nintendo", "ea.com", "riot",
		"blizzard", "ubisoft", "epic", "cod", "minecraft", "roblox", "pubg", "fortnite",
		"valorant", "riotgames", "leagueoflegends", "warzone",
		"apex", "apexlegends", "overwatch", "dota", "csgo",
		"counterstrike", "hearthstone", "battlenet", "battle.net",
		"genshin", "mihoyo", "hoyoverse", "lol", "arenaofvalor", "honorofkings",
	}

	legacyCommunicationKeywords = []string{
		"meet", "zoom", "teams", "voip", "sip", "call", "chat", "conference", "webex",
		"discord", "slack", "telegram", "signal", "whatsapp", "skype", "wechat",
		"voicechat", "videocall", "rtc", "webrtc", "jitsi",
		"mumble", "ventrilo", "teamspeak", "discord.gg",
		"meeting", "conference", "huddle", "gather",
		"qq", "msn", "icq", "line", "kakao", "viber", "imo", "element",
	}

	legacyApiServiceKeywords = []string{
		"api.cloudflare.com", "api.amazonaws.com", "api.azure.com", "googleapis.com",
		"api.fastly.com", "api.maxcdn.com", "api.keycdn.com", "api.bunnycdn.com",
		"api.digitalocean.com", "api.vultr.com", "api.linode.com", "api.hetzner.com",

		"api.vercel.com", "api.netlify.com", "api.heroku.com", "api.railway.app",
		"api.render.com", "api.fly.io", "registry.npmjs.org", "pypi.org",
		"hub.docker.com", "registry.docker.io", "rubygems.org", "crates.io",

		"api.datadog.com", "api.newrelic.com", "api.segment.com", "api.mixpanel.com",
		"api.amplitude.com", "api.hotjar.com", "api.sentry.io", "api.rollbar.com",

		"api.auth0.com", "api.okta.com", "api.twilio.com", "api.sendgrid.com",
		"api.mailgun.com", "api.stripe.com",

		"ecs.aliyuncs.com", "api.qcloud.com", "api.ucloud.cn", "api.huaweicloud.com",
		"api.baidubce.com", "api.volcengine.com",

		"gateway.", "api-gateway.", "apigateway.", "/api/", "/v1/", "/v2/", "/v3/", "/v4/",
		"/rest/", "/graphql/", "rest.", "graphql.", "webhook.", "rpc.",
	}

	legacyDnsServiceKeywords = []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
		"208.67.222.222", "208.67.220.220",

		"dns.google", "dns.google.com", "cloudflare-dns.com", "dns.cloudflare.com",
		"one.one.one.one", "family.cloudflare-dns.com", "security.cloudflare-dns.com",
		"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
		"doh.opendns.com", "doh.familyshield.opendns.com", "doh.sandbox.opendns.com",
		"mozilla.cloudflare-dns.com", "firefox.dns.nextdns.io",
		"dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com",
		"doh.cleanbrowsing.org", "family-filter-dns.cleanbrowsing.org",

		"dot.cloudflare-dns.com", "dot.alidns.com", "dot.dns.sb", "dot.360.cn",

		"doh.pub", "dns.pub", "doh.360.cn", "dns.alidns.com", "doh.alidns.com",
		"doh.dns.sb", "rubyfish.cn", "dns.rubyfish.cn", "pdns.fkgfw.cf",

		"commons.legacyHost", "odvr.nic.cz", "doh.libredns.gr", "dns.digitale-gesellschaft.ch",
		"dns.switch.ch", "jp.tiar.app", "jp.tiarap.org", "kaitain.restena.lu",
		"dns.twnic.tw", "dns.hinet.net",

		"dns", "doh", "doq", "dot", "resolver", "nameserver", "recursive",
		"authoritative", "secure-dns", "private-dns",
	}

	legacyPrivateIPNetworks = []struct {
		prefix   netip.Prefix
		category int
	}{
		// IPv4 private ranges
		{netip.MustParsePrefix("10.0.0.0/8"), 1},
		{netip.MustParsePrefix("172.16.0.0/12"), 1},
		{netip.MustParsePrefix("192.168.0.0/16"), 1},
		{netip.MustParsePrefix("127.0.0.0/8"), 2},
		{netip.MustParsePrefix("169.254.0.0/16"), 3},

		// IPv6 private ranges
		{netip.MustParsePrefix("::1/128"), 2},
		{netip.MustParsePrefix("fe80::/10"), 3},
		{netip.MustParsePrefix("fc00::/7"), 1},
		{netip.MustParsePrefix("2001:db8::/32"), 4},
	}
)

var legacyAllDomainKeywords []keywordEntry

func init() {
	total := len(legacyDnsServiceKeywords) + len(legacyApiServiceKeywords) + len(legacyGameKeywords) +
		len(legacyCommunicationKeywords) + len(legacyStreamingKeywords)
	legacyAllDomainKeywords = make([]keywordEntry, 0, total)
	for _, kw := range legacyDnsServiceKeywords {
		legacyAllDomainKeywords = append(legacyAllDomainKeywords, keywordEntry{kw, 6})
	}
	for _, kw := range legacyApiServiceKeywords {
		legacyAllDomainKeywords = append(legacyAllDomainKeywords, keywordEntry{kw, 5})
	}
	for _, kw := range legacyGameKeywords {
		legacyAllDomainKeywords = append(legacyAllDomainKeywords, keywordEntry{kw, 3})
	}
	for _, kw := range legacyCommunicationKeywords {
		legacyAllDomainKeywords = append(legacyAllDomainKeywords, keywordEntry{kw, 4})
	}
	for _, kw := range legacyStreamingKeywords {
		legacyAllDomainKeywords = append(legacyAllDomainKeywords, keywordEntry{kw, 2})
	}
}

func legacyExtractASNFeature(legacyAsnInfo string) int {
	if legacyAsnInfo == "" {
		return 0
	}

	legacyAsnInfo = strings.ToLower(legacyAsnInfo)

	// Prefer the most specific match, with a stable tie break. Map iteration
	// must not change the feature of the same ASN between connections.
	matched, category := "", 0
	for keyword, value := range legacyAsnCategories {
		if strings.Contains(legacyAsnInfo, keyword) &&
			(len(keyword) > len(matched) || (len(keyword) == len(matched) && keyword < matched)) {
			matched, category = keyword, value
		}
	}
	if matched != "" {
		return category
	}

	s := legacyAsnInfo
	if len(s) >= 2 && s[0] == 'a' && s[1] == 's' {
		s = s[2:]
	}
	j := 0
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j > 0 {
		if asnNum, err := strconv.ParseUint(s[:j], 10, 64); err == nil {
			switch {
			case asnNum < 1000:
				return 50 // early allocation era
			case asnNum < 10000:
				return 51 // older allocation era
			case asnNum < 50000:
				return 52 // mid allocation era
			case asnNum < 150000:
				return 53 // newer allocation era
			default:
				return 54 // latest allocation era
			}
		}
	}

	return 0
}

func legacyExtractGeoIPFeature(geoIPInfo []string) int {
	if len(geoIPInfo) == 0 {
		return 0
	}

	countryCode := ""
	if len(geoIPInfo) > 0 {
		countryCode = geoIPInfo[0]
	}

	if category, exists := legacyGeoCategories[countryCode]; exists {
		return category
	}

	if countryCode != "" {
		hashValue := 0
		for _, r := range countryCode {
			hashValue = hashValue*31 + int(r)
		}
		return 30 + (hashValue % 20)
	}

	return 0
}

func legacyExtractDomainTypeFeature(legacyHost string) int {
	if legacyHost == "" {
		return 0
	}

	legacyHost = strings.ToLower(legacyHost)

	if strings.Contains(legacyHost, "[") {
		return 1
	}
	if _, err := netip.ParseAddr(legacyHost); err == nil {
		return 1
	}

	// keyword matching, the order of legacyAllDomainKeywords decides the priority
	for _, entry := range legacyAllDomainKeywords {
		if strings.Contains(legacyHost, entry.keyword) {
			return entry.category
		}
	}

	if strings.HasSuffix(legacyHost, ".gov") {
		return 14
	} else if strings.HasSuffix(legacyHost, ".edu") {
		return 15
	} else if strings.HasSuffix(legacyHost, ".cn") {
		return 10
	} else if strings.HasSuffix(legacyHost, ".com") {
		return 11
	} else if strings.HasSuffix(legacyHost, ".net") {
		return 12
	} else if strings.HasSuffix(legacyHost, ".org") {
		return 13
	}

	if domainRegex.MatchString(legacyHost) {
		if strings.Count(legacyHost, ".") >= 2 {
			return 30
		}
		return 31
	}

	return 0
}

func legacyExtractIPFeature(ipAddr string) int {
	if ipAddr == "" {
		return 0
	}

	addr, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return 0
	}

	for _, network := range legacyPrivateIPNetworks {
		if network.prefix.Contains(addr) {
			return network.category + 100 // 101-104 are the private IP kinds
		}
	}

	if addr.Is4() {
		return 110 // public IPv4
	} else {
		return 111 // public IPv6
	}
}

// legacyExtractPortFeature returns the port feature code of the model: 30 game, 31 communication,
// 32-34 game or communication ranges, 35 API, 36 DNS, otherwise the well known port category.
func legacyExtractPortFeature(port uint16) int {
	if _, isDNS := legacyDnsServicePorts[port]; isDNS {
		return 36
	}

	if _, isAPI := legacyApiServicePorts[port]; isAPI {
		return 35
	}

	if _, isGame := legacyGameSpecificPorts[port]; isGame {
		return 30
	}

	if _, isComm := legacyCommunicationPorts[port]; isComm {
		return 31
	}

	if category, exists := legacyWellKnownPorts[port]; exists {
		return category
	}

	for _, r := range legacyGameCommRanges {
		if port >= r.min && port <= r.max {
			switch r.category {
			case 1:
				return 32
			case 2:
				return 33
			case 3:
				return 34
			}
		}
	}

	for _, r := range legacyPortRanges {
		if port >= r.min && port <= r.max {
			return r.category
		}
	}

	return 0
}

// legacyDeriveConnectionType returns the connection type code of the model: 1 web, 2 streaming,
// 3 realtime, 4 database, 5 file transfer, 6 API, 7 DNS.
func legacyDeriveConnectionType(port uint16, addressFeature, portFeature int) int {
	if addressFeature == 6 || portFeature == 36 {
		return 7
	}
	if _, isDNS := legacyDnsServicePorts[port]; isDNS {
		return 7
	}

	if addressFeature == 5 || portFeature == 35 {
		return 6
	}
	if _, isAPI := legacyApiServicePorts[port]; isAPI {
		return 6
	}

	if addressFeature == 3 || addressFeature == 4 {
		return 3
	}
	if _, isGamePort := legacyGameSpecificPorts[port]; isGamePort {
		return 3
	}
	if _, isCommPort := legacyCommunicationPorts[port]; isCommPort {
		return 3
	}

	if addressFeature == 2 {
		return 2
	}

	if port == 80 || port == 443 || portFeature == 4 || portFeature == 7 {
		return 1
	}

	if portFeature == 13 || portFeature == 14 || portFeature == 15 || portFeature == 16 {
		return 4
	}

	if port == 20 || port == 21 || port == 22 || port == 989 || port == 990 {
		return 5
	}

	for _, r := range legacyGameCommRanges {
		if port >= r.min && port <= r.max {
			return 3
		}
	}

	if port > 10000 && port < 65000 {
		return 3
	}

	return 0
}
