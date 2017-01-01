# Examples

## Home Agent

* `home_agent.py` - HA implementation
* `ha.cfg` - HA configuration

To start HA service, run following command:
```
# python home_agent.py ha.cfg
```

## Mobile Node Agent

* `mn_agent.py` - MN implementation
* `mn.cfg` - MN configuration

To start MN service, run following command:
```
# python mn_agent.py start mn.cfg
```
to stop MN service:
```
$ python mn_agent.py stop mn.cfg
```
to register using eth0 interface:
```
$ python mn_agent.py register eth0
```
to deregister:
```
$ python mn_agent.py deregister
```
to get status information:
```
$ python mn_agent.py status
```
