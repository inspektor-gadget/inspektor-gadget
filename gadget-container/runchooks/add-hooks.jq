{
	"hooks": {
		"prestart": [
			{
				"path": "/bin/sh",
				"args": ["sh", "-c", "test ! -x /opt/bin/ocihookgadget || /opt/bin/ocihookgadget -hook prestart"]
			}
		],
		"poststop": [
			{
				"path": "/bin/sh",
				"args": ["sh", "-c", "test ! -x /opt/bin/ocihookgadget || /opt/bin/ocihookgadget -hook poststop"]
			}
		]
	}
}
