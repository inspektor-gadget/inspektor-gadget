{
	"hooks": {
		"prestart": [
			{
				"path": "/bin/sh",
				"args": ["sh", "-c", "test ! -x /opt/bin/runc-hook-prestart.sh || /opt/bin/runc-hook-prestart.sh"]
			}
		],
		"poststop": [
			{
				"path": "/bin/sh",
				"args": ["sh", "-c", "test ! -x /opt/bin/runc-hook-poststop.sh || /opt/bin/runc-hook-poststop.sh"]
			}
		]
	}
}
