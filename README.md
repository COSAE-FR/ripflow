# ripflow: simple Netflow 5 probe

## Configuration

The configuration file is in YAML format. 

```shell
$ ./ripflow -ripflow.file /path/to/configuration/file.yml
```

### Logging configuration (logging)

Configure the logs.

```yaml
logging:                       # configure logging properties
  level: debug                 # log level (trace,debug,info,warning,error)
  file: /var/log/riproxy.log   # log file (stderr if not set)
```

#### Level (level)

The log level. Must be one of the following :

- error: used for errors that should definitely be noted.
- warning (or warn): non-critical entries that deserve eyes.
- info: general operational entries about what's going on inside the application.
- debug: usually only enabled when debugging. Very verbose logging.
- trace: designates finer-grained informational events than the Debug.

#### File (file)

The log file. Use stderr if not set.

### Capturing interfaces (interfaces)

Configure interfaces. This is a map of interface names.

```yaml
interfaces:                # Capturing interfaces
  eth0:                    # Capture all traffic from eth0
  eth1:                    # Capture traffic from eth1
    filter: not port 53    # BPF filter: exclude traffic from or to port 53
```

#### Filter

The BPF program to apply to the interface traffic before extracting flows.

## Netflow export configuration (export)

Host and port of the Netflow collector.

```yaml
export:
  host: 127.0.0.1
  port: 9999
```

## Netflow flow cache (cache)

Probe cache configuration

```yaml
cache:
  max: 8192            # Maximum cache size (in flows) before oldest flow eviction occurs (default: 65536)
  idle_timeout: 15     # Number of second accepted between two packets in the same flow (default: 15)
  active_timeout: 1800 # Number of seconds a flow can live (default: 1800)
```

# Credits

Many parts are based on the [goflowd project](https://github.com/rino/goflowd/) by Hitoshi Irino (irino).