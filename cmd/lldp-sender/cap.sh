tcpdump -i any "ether[12:2]=0x88cc"
sudo tcpdump -i lo "ether proto 0x88cc"              