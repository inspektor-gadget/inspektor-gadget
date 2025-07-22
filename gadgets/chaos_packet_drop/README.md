# chaos_packet_drop

This gadget is used to simulate the random packet drops in the network based on independent (Bernoulli) probability model. The program runs at the tc hook point and can be configured to run at ingress/egress and for TCP/UDP packets and the drop probability percentage can also be configured. 
We can also drop packets of a specific IP/port number.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/chaos_packet_drop