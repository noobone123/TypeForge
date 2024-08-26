import pydot
import argparse
import os
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


def load_graphs(dot_dir):
    """
    Load all .dot files in the specified directory and return a big networkx Graph object.
    """
    big_G = nx.Graph()
    
    print(f"Loading graphs from {dot_dir}")
    for filename in os.listdir(dot_dir):
        if filename.endswith(".dot"):
            dot_file = os.path.join(dot_dir, filename)
            graph = pydot.graph_from_dot_file(dot_file)[0]

            for edge in graph.get_edges():
                src = edge.get_source().replace('"', '')
                dst = edge.get_destination().replace('"', '')
                label = edge.get_attributes().get('label', '')

                # Add edges to the networkx graph (as undirected edges)
                big_G.add_edge(src, dst, label=label)
                big_G.add_edge(dst, src, label=label)  # Add the reverse edge as well for undirected graph
                print(f"Added edge: {src} <-> {dst} ({label})")

            print(f"Loaded graph from {dot_file}")

    return big_G


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
                print(f"\033[34m{node}\033[0m --- (\033[31m{edge_label}\033[0m) --- \033[34m{edge[1]}\033[0m")
            else:
                print(f"\033[34m{node}\033[0m")
    else:
        print("No path found.")


def main(G: nx.Graph):
    while True:
        src_node = input("Enter source node: ").strip()
        if src_node not in G.nodes:
            print("Node not found in the graph.")
            continue

        dst_node = input("Enter destination node: ").strip()
        if dst_node not in G.nodes:
            print("Node not found in the graph.")
            continue

        shortest_path_nodes, shortest_path_edges = find_shortest_path(G, src_node, dst_node)
        print_colored_path(shortest_path_nodes, shortest_path_edges, G)


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Graph Explorer")

    # -p: dot file path, specify 1 dot file to load and explore
    # -d: dot files directory, specify a directory to load and explore all dot files in it
    # -p and -d are mutually exclusive
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--path", help="Path to the DOT file")
    group.add_argument("-d", "--dir", help="Path to the directory containing DOT files")

    args = parser.parse_args()

    if args.path:
        G = load_graph(args.path)
    elif args.dir:
        G = load_graphs(args.dir)

    main(G)

