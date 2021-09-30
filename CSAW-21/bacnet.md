# A Pain in the BAC(net) - (50 points, 286 Solves)
**Description**
```
Attached is a packet capture taken from a building management network. One of the analog sensors reported values way outside of its normal operating range. Can you determine the object name of this analog sensor? Flag Format: flag{Name-of-sensor}. For example if the object name of this analog sensor was "Sensor_Temp1", the flag would be flag{Sensor_Temp1}. (Note: because there are a limited number of sensors, we're only giving you two guesses for this challenge, so please check your input carefully.)

Author: CISA
```

This September SIGPwny participated in CSAW 2021 Qualifiers. We placed Second which was really awesome! It was an incredible effort.

This challenge (along with the whole of the ICS suite) was really interesting and fun to work on! We had two people finish it within 5 minutes of eachother without realizing that they did, and we took two different methods. So here are the two methods we have for this challenge!

# Two Methods

## Method 1, Pyshark (Pete)
thomas u did intro already so lets go

Looking at the `bacnet.pcap` file, we can identify a couple types of interesting packet types:

+ units
+ present-value
+ object-name


Based on these pieces of information, we should be able to construct a list of objects, as well every reading per object, and the units used for the readings. This will be incredibly useful in determining if an object is reporting irregular values.


First, we can pull this into `pyshark` and start sifting through packets. Lets filter by `'Complex-ACK'` packets, as we only care about the response, and pull out the IDS into a dictionary.


```py

import pyshark
import json
cap = pyshark.FileCapture("./bacnet.pcap")

objects = {

}
for packet in cap:
    if packet['BACAPP'].type != '3':  # Complex-ACK
        continue
    object_id = packet['BACAPP'].get_field('').split(', ')[1]
    if object_id not in objects:
        objects[object_id] = {}


with open('out.json', 'w') as f:
    f.write(json.dumps(objects, indent=2))
```


Now, lets parse out the packet-types and start making a dictionary in the format of:

```
{
    'object_id': {
        'name': 'ABC',
        'units': 'Lumens',
        'readings': [3000, 1234]
    }
}
```

Code:

```py
import pyshark
import json
cap = pyshark.FileCapture("./bacnet.pcap")

lookup = {
    '117': 'units',
    '85': 'present-value',
    '77': 'object-name',
}

objects = {}

for packet in cap:
    if packet['BACAPP'].type != '3':  # Complex-ACK
        continue
    object_id = packet['BACAPP'].get_field('').split(', ')[1]
    if object_id not in objects:
        objects[object_id] = {}

    try:
        packet_type = lookup[packet['BACAPP'].property_identifier]
    except KeyError:
        continue
    if packet_type == 'present-value':
        if 'readings' not in objects[object_id]:
            objects[object_id]['readings'] = []
        objects[object_id]['readings'].append(
            packet['BACAPP'].get_field('present_value.real'))
    if packet_type == 'units':
        objects[object_id]['units'] = (packet['BACAPP'].__str__().split(
            'units:')[1].split('\n')[0].strip())
    if packet_type == 'object-name':
        objects[object_id]['name'] = packet['BACAPP'].__str__().split('Object Name:')[
            1].split('\n')[0].strip()

with open('out.json', 'w') as f:
    f.write(json.dumps(objects, indent=2))
```

And inspecting our values...:


```
  "7": {
    "name": "Sensor_12345",
    "units": "Kilowatt Hours (19)",
    "readings": [
      "1493.13427734375",
      "1420.12353515625",
      "1446.45324707031",
      "1491.82995605469",
      "1483.56103515625",
      "1467.9677734375",
      "1411.18664550781",
      "1470.427734375",
      "1478.26916503906",
      "1477.85900878906",
      "1431.7744140625",
      "1452.45703125",
      "1436.71887207031",
      "99999.9921875",
      "99999.9921875",
      "99999.9921875",
      "99999.9921875",
      "1432.81823730469",
      "1405.66235351562",
      "1418.33959960938"
    ]
  },
```

We find `'Sensor_12345'` is reporting values way off.


## Method 2, Manual Analysis (Thomas)
We started by opening the PCAP and looking at the method. 

First thing I wanted to do was get the names of all the objects in this list. I quickly wrote `dumpObjNames()` to do that. To get objnames.json I made sure that 'Object Name' Was in the 'BACAPP' field in a wireshark filter. Filtering looked like this
![Image of filtered by objeect name](https://link)

We found 8 "SENSOR_XXXXX" names and 30 or so other random sensors.

Looking around at the packets more, we notice that there is a standard loop of information that follows the following pattern.
1. Get Name
2. Get Units
3. Get Event State
4. Get Out-Of-Service
5. Get Current Value

Next, we needed to find the way to get those values. After looking around there are several methods I noticed.

1. The "Get current value" response packets are of size 65 Bytes every time
2. The get current value response was 8 packets after the name response every time.

We went with method 2, filtering information by the values and names (adding 8 to get the value). see `filterInformation()`

From there we did statistical analysis with `findFunky

<details><summary>bacnet.py</summary>

```python
import json
import statistics as stats
def dumpObjNames():
    out = []
    objs = json.load(open('objnames.json','r'))
    for obj in objs:
        objname = obj['_source']['layers']['bacapp']['Object Name']
        objname = objname.get('bacapp.object_name',None)
        if objname != None and objname not in out:
            print(objname)
            out.append(objname)
    print(len(out),'\n',out)
    of = open('objnames.txt','w')
    for n in out:
        of.write(n + '\n')
    of.close()

def pack_num(packet):
    return packet['_source']['layers']['frame']['frame.number']

def value(packet):
    return packet['_source']['layers']['bacapp'].get('bacapp.present_value.real',None)

def obj_name(packet):
    objName = packet['_source']['layers']['bacapp'].get('Object Name',None)
    return objName.get('bacapp.object_name',None)

def filterInformation():
    filt_pack = {}
    raw_packets = json.load(open('susdevices.json','r'))
    value_packets = json.load(open('values.json','r'))

    values = {}
    for v_packet in value_packets:
        num = pack_num(v_packet)
        val = value(v_packet)
        values[num] = val

    for packet in raw_packets:
        packetNum = pack_num(packet)
        name = obj_name(packet)
        if filt_pack.get(name,None) == None:
            filt_pack[name] = []
        filt_pack[name].append(values[str(int(packetNum) + 8)])
    
    json.dump(filt_pack,open('objectValues.json','w'))
    return filt_pack

def find_funky(filt_pack):
    means = {}
    medians = {}
    ranges = {}
    for obj in filt_pack.keys():
        values = list(map(float,filt_pack[obj]))
        means[obj] = sum(values) / len(values)
        medians[obj] = stats.median(values)
        ranges[obj] = max(values) - min(values)
    json.dump({'means':means,'medians':medians,'ranges':ranges},open('analysis.json','w'))

def main():
    # dumpObjNames()
    f_pack = filterInformation()
    
    find_funky(f_pack)


if __name__ == '__main__':
    main()
```
</details>

Running `find_funky()` on the filtered packets generated the following packet
```json
{
    "means": {
        "Sensor_00001": 22.021586322784437,
        "Sensor_88990": 119.99037551879876,
        "Sensor_67890": 1599.6542602539064,
        "Sensor_66778": 8.309762692451475,
        "Sensor_11223": 51.102356338500975,
        "Sensor_11112": 60.00918083190918,
        "Sensor_12345": 21160.92758178711,
        "Sensor_34455": 31.465178012847893
    },
    "medians": {
        "Sensor_00001": 22.2888526916504,
        "Sensor_88990": 119.9876098632815,
        "Sensor_67890": 1599.3466796875,
        "Sensor_66778": 8.079854965209961,
        "Sensor_11223": 52.6334056854248,
        "Sensor_11112": 60.0052375793457,
        "Sensor_12345": 1469.19775390625,
        "Sensor_34455": 32.7495880126953
    },
    "ranges": {
        "Sensor_00001": 3.569505691528299,
        "Sensor_88990": 0.08583068847599407,
        "Sensor_67890": 9.467407226559999,
        "Sensor_66778": 3.25498580932617,
        "Sensor_11223": 18.7091522216797,
        "Sensor_11112": 0.19357299804690342,
        "Sensor_12345": 98594.32983398438,
        "Sensor_34455": 9.778448104858398
    }
}
```

Looking at *means, there are two clear candidates for what looks off. 67890 and 12345, but the ranges gives it away, one sensor is obviously at a high value. Sensor 12345, upon direct inspection we find that the values of Sensor_12345 spike from their standard values. 

```json
{
    "Sensor_12345": [
      "1493.13427734375",
      "1420.12353515625",
      "1446.45324707031",
      "1491.82995605469",
      "1483.56103515625",
      "1467.9677734375",
      "1411.18664550781",
      "1470.427734375",
      "1478.26916503906",
      "1477.85900878906",
      "1431.7744140625",
      "1452.45703125",
      "1436.71887207031",
      "99999.9921875",
      "99999.9921875",
      "99999.9921875",
      "99999.9921875",
      "1432.81823730469",
      "1405.66235351562",
      "1418.33959960938"
    ]
  }```

  Thus we have our flag `flag{Sensor_12345}`

## Interesting thing to note
As there was only a finite input space for this question, there were many accounts created just to solve this challenge by trying the entire input space. It was interesting to look at the accounts and the timeline of who submitted what and when. I wonder what CSAW organizers found on the backend.

## Conclusion
Overall this was a fun challenge :) Look forward to Finals and next year's CSAW.