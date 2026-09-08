package power

var backgroundPowerListener func()

func init() {
	// The callback lives for the process lifetime, like the background manager.
	backgroundPowerListener, _ = NewEventListener(func(event Type) {
		switch event {
		case SUSPEND:
			SetDevicePaused(true)
		case RESUME:
			SetDevicePaused(false)
		}
	})
}
