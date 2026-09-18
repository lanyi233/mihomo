package power

var backgroundPowerListener func()

func init() {
	// The callback lives for the process lifetime, like the background manager.
	backgroundPowerListener, _ = NewEventListener(func(event Type) {
		switch event {
		case SUSPEND:
			SetDevicePaused(true)
		case RESUME, RESUMEAUTOMATIC:
			// Windows only sends PBT_APMRESUMESUSPEND when the resume was
			// user-triggered. An unattended wake (wake timer, Wake-on-LAN,
			// scheduled task) delivers PBT_APMRESUMEAUTOMATIC on its own, so
			// both must clear the pause or background work never restarts.
			SetDevicePaused(false)
		}
	})
}
