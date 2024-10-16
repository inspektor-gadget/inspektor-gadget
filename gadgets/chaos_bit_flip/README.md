# chaos_bit_flip

This gadget is used to simulate the random bit flips on packets in the network based on independent (Bernoulli) probability model for random packets. The program runs at the tc hook point and can be configured to run at ingress/egress and for TCP/UDP packets and the flip probability percentage can also be configured. We can also flip packets of a specific IP/port number.

Currently, the gadget only flips one random bit. To be extended to flip more than one bit.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/chaos_bit_flip