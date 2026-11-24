# NRF registration DNNs

Set `configuration.dnnList` to advertise the DNNs served by this PCF:

```yaml
configuration:
  dnnList:
    - corp
    - ims
```

Omitting the field (or setting it to null) preserves the previous
`[free5gc, internet]` registration. An explicit empty list, an empty name or a
name containing whitespace is rejected. This changes `pcfInfo.dnnList` in the
profile registered with NRF; it does not provision DNNs in SMF, UPF or subscriber
data. Configure those separately to match the intended deployment.
