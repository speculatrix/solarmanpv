# solarmanpv

This is yet another attempt to discover the solarmanpv protocol by sniffing
the traffic between a Sofar HYD5000ES inverter and Solarman's service.

The long term aim is to be able to write a main in the middle proxy which
the inverter and solarman, and write the logged data to a local store as
well as having it visible in solarman; thus, if Solarman goes away or
they start charging an excessive fee, it will be possible to run your
own monitoring.

Also, having the values may make it possible to make your inverter talk to
an EV smart charger or hot water controller etc, rather than buy a Zappi
and Eddi.


