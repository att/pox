import heapq

def dijkstra(graph, start):
    distances = {node: float('inf') for node in graph}
    distances[start] = 0

    previous_nodes = {node: None for node in graph}

    priority_queue = [(0, start)]

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue)

        if current_distance > distances[current_node]:
            continue

        for neighbor, weight in graph[current_node].items():
            distance = current_distance + weight

            if distance < distances[neighbor]:
                distances[neighbor] = distance
                previous_nodes[neighbor] = current_node
                heapq.heappush(priority_queue, (distance, neighbor))

    return distances, previous_nodes

def get_shortest_path(previous_nodes, start, destination):
    path = []
    current_node = destination

    while current_node != start:
        path.append(current_node)
        current_node = previous_nodes[current_node]

    path.append(start)
    path.reverse()

    return path

def all_pairs_shortest_paths(graph):
    all_shortest_paths = {}

    for start_node in graph:
        distances, previous_nodes = dijkstra(graph, start_node)
        all_shortest_paths[start_node] = {}

        for destination_node in graph:
            if destination_node == start_node:
                continue

            # Utilize the previously computed results
            if destination_node in all_shortest_paths and start_node in all_shortest_paths[destination_node]:
                shortest_path = all_shortest_paths[destination_node][start_node][::-1]
            else:
                shortest_path = get_shortest_path(previous_nodes, start_node, destination_node)

            all_shortest_paths[start_node][destination_node] = shortest_path

    return all_shortest_paths

if __name__ == "__main__":
    graph = {
        'A': {'B': 1, 'C': 4},
        'B': {'A': 1, 'C': 2, 'D': 5},
        'C': {'A': 4, 'B': 2, 'D': 1},
        'D': {'B': 5, 'C': 1}
    }

    all_shortest_paths = all_pairs_shortest_paths(graph)

    for start_node in graph:
        for destination_node in graph:
            if destination_node == start_node:
                continue

            shortest_path = all_shortest_paths[start_node][destination_node]
            print(f"Shortest path from {start_node} to {destination_node}: {shortest_path}")
