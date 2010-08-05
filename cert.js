var cert = {
	"Type":"certificate",
	"Version":"1.0",
	"Serial":17,
	"Issuer":"My Awesome CA",
	"NotBefore":"2010-08-02T01:01:35Z",
	"NotAfter":"2011-08-02T01:01:35Z",
	"Name":"example.com",
	"PublicKey":{
		"Algorithm":"RSA",
		"RsaExponent":"AQAB",
		"RsaModulus":"j7eP58y+X+S2EVAC0yYrTGTyvGRwvPhVxisBIrmFG7F0uBcTGOst6P0wOSa5U1WM40ry6pt0C83+ibJrKZl8v6GKyt7gudQWOZqC/dVYfeCoXUj+LWS/WjT8fFyrn+NgBqK0WQxz+YhGL1Rkvz3pbsKzqVSBbu4151caHX4W5bs="
	},
	"Extensions":[

	],
	"CriticalExtensions":[
		{"Name":"keyUsage",
		 "Value":3}
	]
};

var signed_cert = {
	"Type":"signature",
	"Version": "1.0",
	"SignedData": "ewoJIlZlcnNpb24iOiIxLjAiLAoJIlNlcmlhbCI6MTcsCgkiSXNzdWVyIjoiTXkgQXdlc29tZSBDQSIsCgkiTm90QmVmb3JlIjoiMjAxMC0wOC0wMlQwMTowMTozNVoiLAoJIk5vdEFmdGVyIjoiMjAxMS0wOC0wMlQwMTowMTozNVoiLAoJIk5hbWUiOiJleGFtcGxlLmNvbSIsCgkiUHVibGljS2V5Ijp7CgkJIkFsZ29yaXRobSI6IlJTQSIsCgkJIlJzYUV4cG9uZW50IjoiQVFBQiIsCgkJIlJzYU1vZHVsdXMiOiJqN2VQNTh5K1grUzJFVkFDMHlZclRHVHl2R1J3dlBoVnhpc0JJcm1GRzdGMHVCY1RHT3N0NlAwd09TYTVVMVdNNDByeTZwdDBDODMraWJKcktabDh2NkdLeXQ3Z3VkUVdPWnFDL2RWWWZlQ29YVWorTFdTL1dqVDhmRnlybitOZ0JxSzBXUXh6K1loR0wxUmt2ejNwYnNLenFWU0JidTQxNTFjYUhYNFc1YnM9IgoJfSwKCSJFeHRlbnNpb25zIjpbXQp9", 
	"Signature": {"SignatureAlgorithm": "RSA-PKCS1-1.5",
				  "DigestAlgorithm": "SHA1",
				  "Signer": "My Awesome CA", 
				  "PkixChain": ["eyJ1c2VybmFtZSI6ICJla3JAcnRmbS5jb20iLCAicHVia2V5IjogImV5SmxJam9nTmpVMU16Y3NJQ0p1SWpvZ01UQXdPVEl4TlRNM01qWTJPVFk0T1RVMU1UQXlNakF4Tmprek1qQTFNamc0TXpBME9UY3lcbk1EVTBNREF4TlRVMk16TXlNelV6TURVek5qY3hOVEUzT0RFNU1qUXpPRGN6TWpNeE9EZ3dNek0wTmpFd05qUTVNRE0yTkRNMU1qUTFcbk16YzBOemszTXprNU16YzFNVFkzTVRreE16WTBPVGN5T1RBMU1ESXlNamMzTmpFeU5UZzBNRFl5TkRnNE9UTXpNalV3TkRNNU9EZzBcbk16TTFORE01TURJMU9EQTJOak01TURnek16UTVPVE13TURBME5ERTROamMxTmpNM01ESTNOemszT1RrNE16azNNRFEzTXpRMk1UUXpcbk1ETTVNemMzTkRNMk1qRTFNamt5TXpZMk56YzRORGM0T1RrM05qUXhOamd3TnpJMU5UazBOamMwTnpnMU16RXlPREkxTWpBeU1qRTNcbk9UZ3hOVFkyTlRNM09UVXlNRGswTnpFek1EVTNNREEyT1RVeE1EYzNNakEzTlRZNE9UazVPRFkzZlE9PVxuIn0="],
				  "Value": ""
				 }
};
