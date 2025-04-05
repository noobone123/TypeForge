package typeforge.base.dataflow;

import org.jgrapht.Graph;
import org.jgrapht.graph.SimpleGraph;
import typeforge.utils.Logging;

import java.util.Comparator;
import java.util.NoSuchElementException;
import java.util.Set;

public class ConflictGraph<T> {
    // Edge type enum
    public enum EdgeType {
        INTERSEC,
        NOINTERSEC
    }

    // Custom edge class
    public static class ConflictEdge {
        private final EdgeType type;

        public ConflictEdge(EdgeType type) {
            this.type = type;
        }

        public EdgeType getType() {
            return type;
        }

        @Override
        public String toString() {
            return "ConflictEdge[" + type + "]";
        }
    }

    private final Graph<T, ConflictEdge> graph;

    public ConflictGraph() {
        // Create an undirected graph
        this.graph = new SimpleGraph<>(ConflictEdge.class);
    }

    // Add a vertex to the graph
    public boolean addVertex(T vertex) {
        return graph.addVertex(vertex);
    }

    // Add an edge of type INTERSEC between two vertices
    public void addIntersecEdge(T source, T target) {
        addVertex(source);
        addVertex(target);
        graph.addEdge(source, target, new ConflictEdge(EdgeType.INTERSEC));
        Logging.debug("ConflictGraph", String.format("Add Intersection Conflict Graph edge: %s ---%s---> %s", source, EdgeType.INTERSEC, target));
    }

    // Add an edge of type NOINTERSEC between two vertices
    public void addNoIntersecEdge(T source, T target) {
        addVertex(source);
        addVertex(target);
        graph.addEdge(source, target, new ConflictEdge(EdgeType.NOINTERSEC));
        Logging.debug("ConflictGraph", String.format("Add No Intersection Conflict Graph edge: %s ---%s---> %s", source, EdgeType.NOINTERSEC, target));
    }

    // Get all vertices
    public Set<T> getVertices() {
        return graph.vertexSet();
    }

    // Get all edges
    public Set<ConflictEdge> getEdges() {
        return graph.edgeSet();
    }

    // Find the node with the most connections (highest degree)
    public T findNodeWithMostConnections() {
        Set<T> vertices = graph.vertexSet();

        if (vertices.isEmpty()) {
            throw new NoSuchElementException("Graph is empty");
        }

        return vertices.stream()
                .max(Comparator.comparingInt(graph::degreeOf))
                .orElseThrow();
    }

    // Get the number of edges for a specific vertex
    public int getConnectionCount(T vertex) {
        return graph.degreeOf(vertex);
    }

    // Get the underlying graph
    public Graph<T, ConflictEdge> getGraph() {
        return graph;
    }

    // Get edges of a specific type
    public Set<ConflictEdge> getEdgesOfType(EdgeType type) {
        return graph.edgeSet().stream()
                .filter(edge -> edge.getType() == type)
                .collect(java.util.stream.Collectors.toSet());
    }

    @Override
    public String toString() {
        return "ConflictGraph{vertices=" + graph.vertexSet().size() +
                ", edges=" + graph.edgeSet().size() + "}";
    }
}