#!/bin/bash

# Number of runs
N=10
total_time=0

echo "Running program $N times..."

# Array to store individual times
declare -a times

# Run the program N times and collect timing data
for i in $(seq 1 $N); do
    echo -n "Run $i: "
    # Use time command and capture real time
    start_time=$(date +%s.%N)
    RUST_LOG=info cargo run --release -- --execute
    end_time=$(date +%s.%N)
    
    # Calculate execution time
    execution_time=$(echo "$end_time - $start_time" | bc)
    times[$i]=$execution_time
    
    echo "Time: ${execution_time} seconds"
    total_time=$(echo "$total_time + $execution_time" | bc)
done

# Calculate average
average=$(echo "scale=4; $total_time / $N" | bc)

# Calculate standard deviation
sum_squared_diff=0
for time in "${times[@]}"; do
    diff=$(echo "$time - $average" | bc)
    squared_diff=$(echo "$diff * $diff" | bc)
    sum_squared_diff=$(echo "$sum_squared_diff + $squared_diff" | bc)
done
std_dev=$(echo "scale=4; sqrt($sum_squared_diff / $N)" | bc -l)

echo ""
echo "Results:"
echo "--------"
echo "Total time: $total_time seconds"
echo "Average time: $average seconds"
echo "Standard deviation: $std_dev seconds"