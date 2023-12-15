#!/bin/bash

# Set the duration for tcpdump
duration=60

# Get the full path of the current working directory
current_directory=$(pwd)

# Get the list of container IDs
container_ids=$(docker ps -q)

# Install tcpdump in all containers
for container_id in $container_ids
do
    docker exec $container_id apt-get update
    docker exec $container_id apt-get install -y tcpdump

    # Create a capture directory within each container
    docker exec $container_id mkdir /capture
done

# Echo to indicate that tcpdump is installed in all containers
echo "tcpdump installed in all containers."

# Loop through each container and run tcpdump
for container_id in $container_ids
do
    # Get the container name
    container_name=$(docker inspect --format '{{.Name}}' $container_id | cut -d'/' -f 2)

    # Set the output file name with full path inside the container
    container_output_file="/capture/${container_name}_traffic.pcap"

    # Print the output file path for debugging
    echo "Output file path inside container: $container_output_file"

    # Run tcpdump in the background for the specified duration
    docker exec -d $container_id tcpdump -w $container_output_file -i any -G $duration

    # Print a message for debugging
    echo "Capturing traffic for container $container_name..."
done

# Sleep for the specified duration to capture traffic
sleep $duration

# Copy the captured files from each container to the host machine
for container_id in $container_ids
do
    docker cp $container_id:/capture/. "$current_directory/"
done

# Stop tcpdump in each container
for container_id in $container_ids
do
    docker exec $container_id pkill tcpdump
done

echo "Traffic capture completed."
