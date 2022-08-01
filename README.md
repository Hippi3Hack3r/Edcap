# Edcap
Edcap is a program for removing traffic from packet capture files.

Right now it can selectively remove traffic from specific IP addresses, as well as mask the domains in dns requests with a replacement of your choice.

#### A note about masking dns requests
This program only changes the domain requested. One could easily use the answer two the request and the time of the request to do
a reverse lookup for the domain. It also doesn't work yet.

## Usage
The binary is available under releases.
You will need to specify a few options:
* removesrc: an IP address to remove. When paired with removedst, the program will remove all traffic between the two.
This is bidirectional, to remove only traffic from src -> dst and not vice versa also specify `-uni=True` (once it's implemented)

## Examples
`./ed -removesrc=192.168.10.2` (removes all traffic to and from 192.168.10.2)

`./ed -removesrc=192.168.10.2 -uni` (removes all traffic from 192.168.10.2, but not packets going to that address)

`./ed -removesrc=192.168.10.2 -dstipnot=192.168.12.3` (removes all traffic going from 192.168.10.2 to any address except 192.168.12.3)

`./ed -removesrc=192.168.10.2 -removedst=192.168.12.3` (removes all traffic between 192.168.10.2 and 192.168.12.3)

## Who is Ed
Ed Galbraith, whom this project is named after, is the Character from Breaking Bad who
helps people disappear and poses as a vacuum cleaner repair man.
