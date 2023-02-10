rule WordPress {
	meta:
		author = "tatsui"
	strings:
		$s1 = "/wp-(?:content|includes)/"
	condition:
		any of them
}

rule Yoast_SEO {
	meta:
		author = "tatsui"
	strings:
		$s1 = "This site is optimized with the Yoast"
		$s2 = "SEO plugin v"
	condition:
		all of them
}

rule GoogleFontAPI {
	meta:
		author = "tatsui"
	strings:
		$s1 = /<link[^>]* href=[^>]+fonts\.(googleapis|google)\.com/
	condition:
		any of them
}

rule jQuery {
	meta:
		author = "tatsui"
	strings:
		$s1 = /jquery.*\.js/
	condition:
		any of them
}

rule Bootstrap {
	meta:
		author = "tatsui"
	strings:
		$s1 = /<link[^>]* href=[^>].*bootstrap.*(\.min)?\.css/
	condition:
		any of them
}

rule GoogleAnalytics {
	meta:
		author = "tatsui"
	strings:
		$s1 = /google-analytics\.com\/(ga|urchin|analytics)\.js/
	condition:
		any of them
}

rule GoogleAdSense {
	meta:
		author = "tatsui"
	strings:
		$s1 = "googlesyndication.com/"
	condition:
		any of them
}

rule GoogleTagManager {
	meta:
		author = "tatsui"
	strings:
		$s1 = /googletagmanager\.com\/gtag\/js/
	condition:
		any of them
}

rule GoogleSignIn {
	meta:
		author = "tatsui"
	strings:
		$s1 = /<meta[^>]*google-signin-client_id/
	condition:
		any of them
}

rule Facebook {
	meta:
		author = "tatsui"
	strings:
		$s1 = /connect\.facebook\.([a-z]+)\/[^\/]*\/[a-z]*\.js/
	condition:
		any of them
}

rule Linkedin_Insight_Tag {
	meta:
		author = "tatsui"
	strings:
		$s1 = "snap.licdn.com/li.lms-analytics/insight.min.js"
	condition:
		any of them
}

rule reCAPTCHA {
	meta:
		author = "tatsui"
	strings:
		$s1 = /\/recaptcha\/api\.js/
	condition:
		any of them
}

rule Cookiebot {
	meta:
		author = "tatsui"
	strings:
		$s1 = "consent.cookiebot.com"
	condition:
		any of them
}

rule CloudflareBrowserInsights {
	meta:
		author = "tatsui"
	strings:
		$s1 = /static\.cloudflareinsights\.com\/beacon(\.min)\.js/
	condition:
		any of them
}

rule PHP {
	meta:
		author = "tatsui"
	strings:
		$s1 = ".php?"
	condition:
		any of them
}

rule Stripe {
	meta:
		author = "tatsui"
	strings:
		$s1 = "js.stripe.com"
	condition:
		any of them
}

rule ApplePay {
	meta:
		author = "tatsui"
	strings:
		$s1 = "<script id=\"apple-pay"
	condition:
		any of them
}

rule AmazonPay {
	meta:
		author = "tatsui"
	strings:
		$s1 = "<meta id=\"amazon-payments"
	condition:
		any of them
}

rule Shopify {
	meta:
		author = "tatsui"
	strings:
		$s1 = /<link[^>]+=['"]\/\/cdn\.shopify\.com/
	condition:
		any of them
}

rule Microsoft_ASP_NET {
	meta:
		author = "tatsui"
	strings:
		$s1 = /<input[^>]+name="__VIEWSTATE/
		$s2 = ".aspx?"
	condition:
		any of them
}

rule React_js {
	meta:
		author = "tatsui"
	strings:
		$s1 = /<[^>]+data-react/
	condition:
		any of them
}

rule Angular_JS {
	meta:
		author = "tatsui"
	strings:
		$s1 = /\bangular.{0,32}\.js/
	condition:
		any of them
}

rule Gatsby {
	meta:
		author = "tatsui"
	strings:
		$s1 = "<div id=\"___gatsby\">"
	condition:
		any of them
}

rule Weebly {
	meta:
		author = "tatsui"
	strings:
		$s1 = /cdn\d+\.editmysite\.com/
	condition:
		any of them
}
