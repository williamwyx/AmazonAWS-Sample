/*
 * Copyright 2010 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * 
 * Modified by Sambit Sahu
 * Modified by Kyung-Hwa Kim (kk2515@columbia.edu)
 * 
 * 
 */
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.PropertiesCredentials;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.DescribeKeyPairsResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceState;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.KeyPair;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.StartInstancesRequest;
import com.amazonaws.services.ec2.model.StopInstancesRequest;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.TerminateInstancesRequest;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class AwsSample {

	/*
	 * Important: Be sure to fill in your AWS access credentials in the
	 * AwsCredentials.properties file before you try to run this sample.
	 * http://aws.amazon.com/security-credentials
	 */

	static AmazonEC2 ec2;

	public static void main(String[] args) throws Exception {

		AWSCredentials credentials = new PropertiesCredentials(
				AwsSample.class
						.getResourceAsStream("AwsCredentials.properties"));

		/*********************************************
		 * 
		 * #1 Create Amazon Client object
		 * 
		 *********************************************/
		System.out.println("#1 Create Amazon Client object");
		ec2 = new AmazonEC2Client(credentials);

		try {

			/*********************************************
			 * 
			 * #2 Describe Availability Zones.
			 * 
			 *********************************************/
			System.out.println("#2 Describe Availability Zones.");
			DescribeAvailabilityZonesResult availabilityZonesResult = ec2
					.describeAvailabilityZones();
			System.out.println("You have access to "
					+ availabilityZonesResult.getAvailabilityZones().size()
					+ " Availability Zones.");

			/*********************************************
			 * 
			 * #3 Describe Available Images
			 * 
			 *********************************************/
			/*
			 * System.out.println("#3 Describe Available Images");
			 * DescribeImagesResult dir = ec2.describeImages(); List<Image>
			 * images = dir.getImages(); System.out.println("You have " +
			 * images.size() + " Amazon images");
			 */

			/*********************************************
			 * 
			 * #4 Describe Current Instances
			 * 
			 *********************************************/
			System.out.println("#4 Describe Current Instances");
			DescribeInstancesResult describeInstancesRequest = ec2
					.describeInstances();
			List<Reservation> reservations = describeInstancesRequest
					.getReservations();
			Set<Instance> instances = new HashSet<Instance>();
			// add all instances to a Set.
			for (Reservation reservation : reservations) {
				instances.addAll(reservation.getInstances());
			}

			System.out.println("You have " + instances.size()
					+ " Amazon EC2 instance(s).");
			for (Instance ins : instances) {

				// instance id
				String instanceId = ins.getInstanceId();

				// instance state
				InstanceState is = ins.getState();
				System.out.println(instanceId + " " + is.getName());
			}

			/*********************************************
			 * 
			 * #5 Create an Instance
			 * 
			 *********************************************/
			System.out.println("#5 Create an Instance");
			/* Create Security Group */
			String my_security_group = "MySecurityGroup";
			CreateSecurityGroupRequest csgr = new CreateSecurityGroupRequest();
			csgr.withGroupName(my_security_group).withDescription(
					"6998 security group");
			CreateSecurityGroupResult createSecurityGroupResult = ec2
					.createSecurityGroup(csgr);

			/* Add SSH */
			IpPermission sshPermission = new IpPermission();
			sshPermission.withIpRanges("0.0.0.0/0").withIpProtocol("tcp")
					.withFromPort(22).withToPort(22);
			/* Add HTTP */
			IpPermission httpPermission = new IpPermission();
			httpPermission.withIpRanges("0.0.0.0/0").withIpProtocol("tcp")
					.withFromPort(80).withToPort(80);

			AuthorizeSecurityGroupIngressRequest authorizeSecurityGroupIngressRequest = new AuthorizeSecurityGroupIngressRequest();
			authorizeSecurityGroupIngressRequest.withGroupName(
					my_security_group).withIpPermissions(sshPermission,
					httpPermission);

			ec2.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);

			/* Create key pair */
			String my_key_pair = "Cloud2015";
			CreateKeyPairRequest createKeyPairRequest = new CreateKeyPairRequest();
			createKeyPairRequest.withKeyName(my_key_pair);

			CreateKeyPairResult createKeyPairResult = ec2
					.createKeyPair(createKeyPairRequest);

			KeyPair keyPair = new KeyPair();
			keyPair = createKeyPairResult.getKeyPair();
			String privateKey = keyPair.getKeyMaterial();

			String keyFileName = my_key_pair + ".pem";
			File keyFile = new File(keyFileName);
			BufferedWriter bw = new BufferedWriter(new FileWriter(keyFile));
			BufferedReader br = new BufferedReader(new StringReader(privateKey));
			char buf[] = new char[1024];
			int len;
			while ((len = br.read(buf)) != -1) {
				bw.write(buf, 0, len);
			}
			bw.flush();
			bw.close();
			br.close();
			Runtime.getRuntime().exec("chmod 400 " + keyFileName);

			/* Run a new Instance */
			String imageId = "ami-76f0061f"; // Basic 32-bit Amazon Linux AMI
			int minInstanceCount = 1; // create 1 instance
			int maxInstanceCount = 1;

			RunInstancesRequest rir = new RunInstancesRequest(imageId,
					minInstanceCount, maxInstanceCount);
			rir.withKeyName(my_key_pair).withSecurityGroups(my_security_group);
			RunInstancesResult result = ec2.runInstances(rir);

			/* get instanceId from the result */
			List<Instance> resultInstance = result.getReservation()
					.getInstances();
			List<String> createdInstanceIds = new ArrayList<String>();
			String createdInstanceId = null;
			for (Instance ins : resultInstance) {
				createdInstanceId = ins.getInstanceId();
				System.out.println("New instance has been created: "
						+ ins.getInstanceId());
				createdInstanceIds.add(createdInstanceId);
			}

			/*********************************************
			 * 
			 * #6 Create a 'tag' for the new instance.
			 * 
			 *********************************************/
			System.out.println("#6 Create a 'tag' for the new instance.");
			List<String> resources = new LinkedList<String>();
			List<Tag> tags = new LinkedList<Tag>();
			Tag nameTag = new Tag("Name", "MyFirstInstance");

			resources.add(createdInstanceId);
			tags.add(nameTag);

			CreateTagsRequest ctr = new CreateTagsRequest(resources, tags);
			ec2.createTags(ctr);
			
			/*********************************************
			 * 
			 * #7 Describe Key Pair
			 * 
			 *********************************************/
			System.out.println("#7 Describe Key Pair");
			DescribeKeyPairsResult dkr = ec2.describeKeyPairs();
			System.out.println(dkr.toString());

			/*********************************************
			 * 
			 * #8 Get IP Address
			 * 
			 *********************************************/
			System.out.println("#8 Get IP address");
			String public_ip = null;
			DescribeInstancesRequest dIrequest = new DescribeInstancesRequest();
			dIrequest.setInstanceIds(createdInstanceIds);

			DescribeInstancesResult dIresult = ec2.describeInstances(dIrequest);
			List<Reservation> dIreservations = dIresult.getReservations();

			List<Instance> dIinstances;
			for (Reservation res : dIreservations) {
				dIinstances = res.getInstances();
				for (Instance ins : dIinstances) {
					public_ip = ins.getPublicIpAddress();
					if (public_ip != null) {
						System.out.println("The private IP is: "
								+ ins.getPrivateIpAddress());
						System.out.println("The public IP is: "
								+ ins.getPublicIpAddress());
					}
				}
			}

			while (public_ip == null) {
				Thread.currentThread().sleep(15000);
				dIresult = ec2.describeInstances(dIrequest);
				dIreservations = dIresult.getReservations();

				for (Reservation res : dIreservations) {
					dIinstances = res.getInstances();
					for (Instance ins : dIinstances) {
						public_ip = ins.getPublicIpAddress();
						if (public_ip != null) {
							System.out.println("The private IP is: "
									+ ins.getPrivateIpAddress());
							System.out.println("The public IP is: "
									+ ins.getPublicIpAddress());
						}
					}
				}
			}

			/*********************************************
			 * 
			 * #9 SSH to the instance
			 * 
			 *********************************************/
			System.out.println("#9 SSH to the instance");
			JSch jsch = new JSch();
			jsch.addIdentity(keyFileName);
			jsch.setConfig("StrictHostKeyChecking", "no");
			Session session = jsch.getSession("ec2-user", public_ip, 22);
			
			boolean done = false;
			while (!done) {
				try {
					session.connect();
					Channel channel = session.openChannel("shell");
					channel.setInputStream(System.in);
					channel.setOutputStream(System.out);
					channel.connect();
					done = true;
				}
				catch (Exception e) {
				}
				Thread.currentThread().sleep(15000);
			}

			/*********************************************
			 * 
			 * #10 Stop/Start an Instance
			 * 
			 *********************************************/
			System.out.println("#10 Stop the Instance");
			List<String> instanceIds = new LinkedList<String>();
			instanceIds.add(createdInstanceId);

			// stop
			StopInstancesRequest stopIR = new StopInstancesRequest(instanceIds);
			// ec2.stopInstances(stopIR);

			// start
			StartInstancesRequest startIR = new StartInstancesRequest(
					instanceIds);
			// ec2.startInstances(startIR);

			/*********************************************
			 * 
			 * #11 Terminate an Instance
			 * 
			 *********************************************/
			System.out.println("#11 Terminate the Instance");
			TerminateInstancesRequest tir = new TerminateInstancesRequest(
					instanceIds);
			// ec2.terminateInstances(tir);

			/*********************************************
			 * 
			 * #12 shutdown client object
			 * 
			 *********************************************/
			ec2.shutdown();

		} catch (AmazonServiceException ase) {
			System.out.println("Caught Exception: " + ase.getMessage());
			System.out.println("Reponse Status Code: " + ase.getStatusCode());
			System.out.println("Error Code: " + ase.getErrorCode());
			System.out.println("Request ID: " + ase.getRequestId());
		}

	}
}
