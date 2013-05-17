package zenoss

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

const IpAddress = "ipAddress"
const IpAddressString = "ipAddressString"
const Uid = "uid"
const DeviceName = "name"
const Keys = "keys"
const Sort = "sort"
const Params = "params"
const Start = "start"
const Limit = "limit"
const Severity = "severity"
const SortDirection = "dir"
const SortDecending = "DESC"
const EventState = "eventState"
const Device = "device"
const Component = "component"
const EventClass = "eventClass"
const EventClassKey = "evclasskey"
const ShortEventClass = "evclass"
const Summary = "summary"

const DefaultDeviceClass = "/zport/dmd/Devices"

// Configuration for a Zenoss connection
type Config struct {

	// Specifies the URL through which Zenoss should be contacted. This must
	// be non-nil as there is no appropriate default. This URL should contain
	// the scheme (HTTP/HTTPs), any required user credentials (user:pwd), and
	// the hostname of the Zenoss server. (ex. https://joe:secret@zenoss.company.com:8443)
	Url *url.URL

	// Flag to indicate if when attempting to connect to Zenoss TLS certificates
	// should be by-passed. This allows the library to work when the caller would
	// like to connect via HTTP, but the host certificates have not been
	// properly installed. This flag enables the caller to by-pass security checks
	// and should be used at the caller own risk
	BypassTlsCertificates bool
}

// Structure that represents a connection to a Zenoss JSON API server.
type Zenoss struct {
	url          *url.URL
	bypassCerts  bool
	requestCount int64
}

// Defined message routers
const EventsRouter = "EventsRouter"
const ProcessRouter = "Processrouter"
const ServiceRouter = "ServiceRouter"
const DeviceRouter = "DeviceRouter"
const NetworkRouter = "NetworkRouter"
const TemplateRouter = "TemplateRouter"
const DetailNavRouter = "DetailNavRouter"
const ReportRouter = "ReportRouter"
const MibRouter = "MibRouter"
const ZenPackRouter = "ZenPackRouter"

// Map that is used to "map" from a message router name to the path element
// in the Zenoss request URL
var routerMap = map[string]string{
	EventsRouter:    "evconsole",
	ProcessRouter:   "process",
	ServiceRouter:   "service",
	DeviceRouter:    "device",
	NetworkRouter:   "messaging",
	TemplateRouter:  "template",
	DetailNavRouter: "detailnav",
	ReportRouter:    "report",
	MibRouter:       "mib",
	ZenPackRouter:   "zenpack",
}

// Executes the HTTP JSON request against the Zenoss server and returns the
// result of the request as a JSON object unmashalled into a generic string to
// interface map.
func (z *Zenoss) routerRequest(router string, method string, data map[string]interface{}) (map[string]interface{}, error) {
	var err error
	var bpayload []byte

	// start stitching together the request url based on the specified router.
	// we could do better error checking here to make sure the router specified
	// actually exists.
	zenurl := z.url.String() + "/zport/dmd/" + routerMap[router] + "_router"

	// construct the payload for the request, which consists of the action/
	// method specification as well as the caller specified data. we generate
	// a incremental request id
	payload := make(map[string]interface{})
	payload["action"] = router
	payload["method"] = method
	payload["type"] = "rpc"
	payload["data"] = []interface{}{data}
	payload["tid"] = fmt.Sprintf("%d", z.requestCount)
	z.requestCount++

	// convert the payload to a JSON object for transmission
	bpayload, err = json.Marshal(payload)
	var response *http.Response

	// ok decision time. often when Zenoss is installed it is installed to be
	// accessed using TLS (https), but the certificate for the host is not
	// always configured. to get around this, i have added an option to
	// ignore certificates. this option should be used at the caller own risk,
	// it is a better solution to simply correctly establish a TLS cert.
	var client *http.Client
	if z.bypassCerts {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		tr := &http.Transport{}
		client = &http.Client{Transport: tr}
	}

	// Perform the actually request
	if response, err = client.Post(zenurl, "application/json", bytes.NewReader(bpayload)); err != nil {
		return nil, err
	}

	// If a valid response was not returned, to this into an error
	if int(response.StatusCode/100) != 2 {
		return nil, fmt.Errorf("Invalid HTTP response: %s", response.Status)
	}

	// Unmashall the response and return it
	var reply map[string]interface{}
	defer response.Body.Close()
	if err = json.NewDecoder(response.Body).Decode(&reply); err != nil {
		return nil, fmt.Errorf("Unable to decode HTTP response : %s", err.Error())
	}
	return reply, nil
}

// Creates a connection to Zenoss using the specified connection string, which
// is meant to be a string representation of a URL for the Zenoss server. The
// connection string should contain the user credentials if required. The
// connection generated from this method call will not by-pass TLS certificates.
// This method call is the equivalent of calling DialConfig with only the
// URL initialized in the Config structure
func Dial(connectionString string) (*Zenoss, error) {
	var connectionUrl *url.URL
	var err error

	if connectionUrl, err = url.Parse(connectionString); err != nil {
		return nil, err
	}

	config := Config{Url: connectionUrl}
	return DialConfig(config)
}

// Creates a connection to Zenoss using the specified configuration. This form
// of creating a connection allows the caller to have finer grain control of
// the configuration
func DialConfig(config Config) (*Zenoss, error) {
	z := new(Zenoss)
	z.bypassCerts = config.BypassTlsCertificates
	z.url = config.Url
	return z, nil
}

// Uses simply heuristics in an attempt to determine if the specified value is
// an IP address or not. This utilizes the "net" package's capability to parse
// the value as an IP as the determining factor.
func isIpAddress(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil
}

// Lookup a device by the given key, which can be either an IP address or the
// name of the device. If no device with the given key can be found then nil is
// returned. The attributes parameter allows the caller to specify which
// attributes of a device should be returned as part of the query. If attributes
// is nil then all available attributes will be returned
func (z *Zenoss) LookupDeviceWithAttributes(key string, attributes []string) (map[string]interface{}, error) {

	// Construct the parameters for the request
	params := make(map[string]interface{})
	if isIpAddress(key) {
		params[IpAddress] = key
	} else {
		params[DeviceName] = key
	}

	// Stitch together the data for the request
	data := map[string]interface{}{
		Params: params,
		Sort:   DeviceName,
		Start:  0,
		Limit:  1}

	// If attributes were specified then add them to the request
	if attributes != nil {
		data[Keys] = attributes
	}

	// Process the request
	var reply map[string]interface{}
	var err error
	if reply, err = z.routerRequest(DeviceRouter, "getDevices", data); err != nil {
		return nil, err
	}

	// This very confusing statement dereferences and does type assertions
	// deep into the map structre.
	result := reply["result"].(map[string]interface{})
	devices := result["devices"].([]interface{})
	if len(devices) > 0 {
		return devices[0].(map[string]interface{}), nil
	}

	// Not found
	return nil, nil
}

// Lookup a device by the given key, which can be either an IP address or the
// name of the device. If no device with the given key can be found then nil is
// returned. This method is the eqivalent of calling LookupDeviceWithAttributes
// passing nil value for the attribute list.
func (z *Zenoss) LookupDevice(key string) (map[string]interface{}, error) {
	return z.LookupDeviceWithAttributes(key, nil)
}

// Return all the devices in the specified device class. If deviceClass is ""
// the a default device class of '/zport/dmd/Devices' is used
func (z *Zenoss) GetDevicesInClass(deviceClass string) ([]map[string]interface{}, error) {

	var useDeviceClass string = deviceClass
	if useDeviceClass == "" {
		useDeviceClass = DefaultDeviceClass
	}

	data := map[string]interface{}{
		Uid:    useDeviceClass,
		Params: make(map[string]interface{})}

	var reply map[string]interface{}
	var err error
	if reply, err = z.routerRequest(DeviceRouter, "getDevices", data); err != nil {
		return nil, err
	}

	result := reply["result"].(map[string]interface{})
	return result["devices"].([]map[string]interface{}), nil
}

// Return all devices. This is equivalent of calling GetDevicesInClass with
// and empty string ("") as the deviceClass parameter
func (z *Zenoss) GetDevices() ([]map[string]interface{}, error) {
	return z.GetDevicesInClass("")
}

// Query events for a given device, component, and event class. All values can
// be passed as empty strings (""), which indicates a wildcard.
func (z *Zenoss) GetEvents(device string, component string,
	eventClass string) ([]map[string]interface{}, error) {

	data := map[string]interface{}{
		Start:         0,
		Limit:         100,
		SortDirection: SortDecending,
		Sort:          Severity}

	severities := []int{5, 4, 3, 2}
	eventStates := []int{0, 1}

	params := map[string]interface{}{
		Severity:   severities,
		EventState: eventStates}

	if device != "" {
		params[Device] = device
	}

	if component != "" {
		params[Component] = component
	}

	if eventClass != "" {
		params[EventClass] = eventClass
	}
	data[Params] = params

	var reply map[string]interface{}
	var err error
	if reply, err = z.routerRequest(EventsRouter, "query", data); err != nil {
		return nil, err
	}

	result := reply["result"].(map[string]interface{})
	return result["devices"].([]map[string]interface{}), nil
}

// Query all events. This is equivalent of calling GetEvents will all parameters
// specified as the empty string ("")
func (z *Zenoss) GetAllEvents() ([]map[string]interface{}, error) {
	return z.GetEvents("", "", "")
}

// Create the specified event on the specified device
func (z *Zenoss) CreateEventOnDevice(device string, severity string,
	summary string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		Device:          device,
		Severity:        severity,
		Summary:         summary,
		Component:       "",
		EventClassKey:   "",
		ShortEventClass: ""}

	return z.routerRequest(EventsRouter, "add_event", data)
}

// Adds the specified device to Zenoss
func (z *Zenoss) AddDevice(deviceName string, deviceClass string) (map[string]interface{}, error) {

	data := map[string]interface{}{
		"deviceName":  deviceName,
		"deviceClass": deviceClass}

	return z.routerRequest(DeviceRouter, "addDevice", data)
}
