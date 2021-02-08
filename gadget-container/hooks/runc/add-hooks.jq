{
	"hooks": {
		"prestart": [
			{
				"path": "/bin/sh",
				"args": ["sh", "-c", "test ! -x /opt/hooks/oci/prestart.sh || /opt/hooks/oci/prestart.sh"]
			}
		],
		"poststop": [
			{
				"path": "/bin/sh",
				"args": ["sh", "-c", "test ! -x /opt/hooks/oci/poststop.sh || /opt/hooks/oci/poststop.sh"]
			}
		]
	}
}
