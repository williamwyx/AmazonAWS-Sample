# AmazonAWS-Sample
A Amazon AWS sample to programmatically create, configure and ssh to a new instance.

This sample program will create a new instance, set security group to allow SSH and HTTP, then use jcsh to ssh to the new instance.

The connection will retry every 15 seconds if last attemp failed.
