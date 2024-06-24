import pydot
import networkx as nx

def load_graph(dot_file):
    """
    Load a graph from a DOT file and return a networkx Graph object.
    """
    graph = pydot.graph_from_dot_file(dot_file)[0]

    G = nx.Graph()

    for edge in graph.get_edges():
        src = edge.get_source()
        dst = edge.get_destination()
        label = edge.get_attributes().get('label', '')  # Safely get label attribute

        # Remove quotes from the node names
        src = src.replace('"', '')
        dst = dst.replace('"', '')

        # Add edges to the networkx graph (as undirected edges)
        G.add_edge(src, dst, label=label)
        G.add_edge(dst, src, label=label)  # Add the reverse edge as well for undirected graph
        print(f"Added edge: {src} <-> {dst} ({label})")

    return G

def find_shortest_path(G, src, dst):
    """
    Find the shortest path from source node to destination node in the graph.
    Return the shortest path as a list of nodes and edges.
    """
    try:
        shortest_path_nodes = nx.shortest_path(G, source=src, target=dst)
        shortest_path_edges = list(zip(shortest_path_nodes[:-1], shortest_path_nodes[1:]))
        return shortest_path_nodes, shortest_path_edges
    except nx.NetworkXNoPath:
        return None, None

def print_colored_path(shortest_path_nodes, shortest_path_edges, G):
    """
    Print the shortest path with edges colored and formatted.
    """
    if shortest_path_nodes:
        for i, node in enumerate(shortest_path_nodes):
            if i < len(shortest_path_edges):
                edge = shortest_path_edges[i]
                edge_label = G.edges[edge]['label']
                print(f"\033[34m{node}\033[0m --- (\033[31m{edge_label}\033[0m) ---> \033[34m{edge[1]}\033[0m")
            else:
                print(f"\033[34m{node}\033[0m")
    else:
        print("No path found.")

if __name__ == "__main__":
    dot_file = "../dummy/TypeAliasGraph_862eb0b9.dot"
    G = load_graph(dot_file)

    while True:
        src_node = input("Enter source node (or 'exit' to quit): ").strip()
        if src_node.lower() == 'exit':
            break

        dst_node = input("Enter destination node: ").strip()

        shortest_path_nodes, shortest_path_edges = find_shortest_path(G, src_node, dst_node)
        print_colored_path(shortest_path_nodes, shortest_path_edges, G)
