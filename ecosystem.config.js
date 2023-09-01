module.exports = {
	apps : [{
		name: "rest-api-widevine",
		script: "./src/run.py",
		watch: false,
		exec_mode: "fork",
		autorestart: true,
		restart_delay: 2000,
		max_restarts: 5,
		interpreter: '/usr/bin/python3',
	}]
}
