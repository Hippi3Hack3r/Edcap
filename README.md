# Edcap
Edcap is a program for selectively removing traffic from capture files.

It can remove traffic between two hosts, from a single host, or between a host and not another host.

Dns replacement is in the works, but as of the writing of this, it only works when the specified replacement string and the new string are the same length.

#### A note about masking dns requests
This program only changes the domain requested. One could easily use the answer two the request and the time of the request to do
a reverse lookup for the domain. It also doesn't work yet.

## Usage
Binaries for Mac and Linux are available under releases.
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
