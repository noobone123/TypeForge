package typeforge.base.dataflow.TFG;

import org.jgrapht.Graph;
import org.jgrapht.alg.connectivity.ConnectivityInspector;
import org.jgrapht.alg.connectivity.KosarajuStrongConnectivityInspector;
import org.jgrapht.alg.interfaces.StrongConnectivityAlgorithm;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.Graphs;

import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.utils.Logging;

import java.util.*;

public class TypeFlowGraph<T> {
    public enum EdgeType {
        CALL,
        RETURN,
        DATAFLOW,
        ALIAS,
    }

    public static class TypeFlowEdge extends DefaultEdge {
        private final EdgeType type;

        public TypeFlowEdge(EdgeType type) {
            this.type = type;
        }

        public EdgeType getType() {
            return type;
        }

        @Override
        public String toString() {
            var source = this.getSource();
            var target = this.getTarget();
            return String.format("%s ---%s---> %s", source, type, target);
        }
    }

    private final Graph<T, TypeFlowEdge> graph;
    private final UUID uuid;
    private final String shortUUID;

    public TypeFlowPathManager<T> pathManager;
    public Skeleton finalSkeleton;

    public TypeFlowGraph() {
        graph = new DefaultDirectedGraph<>(TypeFlowEdge.class);
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        pathManager = new TypeFlowPathManager<T>(this);

        Logging.trace("TypeFlowGraph", String.format("Create TypeFlowGraph_%s", shortUUID));
    }

    public String getShortUUID() {
        return shortUUID;
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        graph.addVertex(src);
        graph.addVertex(dst);
        graph.addEdge(src, dst, new TypeFlowEdge(edgeType));
        Logging.trace("TypeFlowGraph", String.format("TypeFlowGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        graph.removeEdge(src, dst);
        Logging.debug("TypeFlowGraph", String.format("TypeFlowGraph_%s Remove edge: %s ---> %s", shortUUID, src, dst));
    }

    public void removeNode(T node) {
        graph.removeVertex(node);
        Logging.trace("TypeFlowGraph", String.format("TypeFlowGraph_%s Remove node: %s", shortUUID, node));
    }

    /**
     * If a graph has individual single nodes, it is invalid
     */
    public boolean isValid() {
        // If there is only one node, it is valid
        if (graph.vertexSet().size() == 1) {
            return true;
        } else if (graph.vertexSet().isEmpty()) {
            Logging.error("TypeFlowGraph",
                    String.format("Unexpected empty graph: %s", this));
            return false;
        } else {
            boolean isValid = true;
            for (var node: getNodes()) {
                if (graph.inDegreeOf(node) == 0 && graph.outDegreeOf(node) == 0) {
                    isValid = false;
                    break;
                }
            }

            return isValid;
        }
    }

    public int getNumNodes() {
        return graph.vertexSet().size();
    }

    public Set<T> getNodes() {
        return graph.vertexSet();
    }

    public Set<TypeFlowEdge> getEdges() {
        return graph.edgeSet();
    }

    public Graph<T, TypeFlowEdge> getGraph() {
        return graph;
    }

    public Set<T> getForwardNeighbors(T node) {
        var result = new HashSet<T>();
        for (var edge: graph.outgoingEdgesOf(node)) {
            var target = graph.getEdgeTarget(edge);
            result.add(target);
        }
        return result;
    }

    public void mergeGraph(TypeFlowGraph<T> other) {
        for (T vertex: other.getNodes()) {
            graph.addVertex(vertex);
        }

        Set<TypeFlowEdge> edges = other.getGraph().edgeSet();
        for (TypeFlowEdge edge: edges) {
            T src = other.getGraph().getEdgeSource(edge);
            T dst = other.getGraph().getEdgeTarget(edge);
            var EdgeType = edge.getType();

            TypeFlowEdge existingEdge = graph.getEdge(src, dst);
            if (existingEdge == null) {
                graph.addEdge(src, dst, new TypeFlowEdge(EdgeType));
            } else if (existingEdge.getType() != EdgeType) {
                Logging.warn("TypeFlowGraph", String.format("%s Merge conflict: %s ---> %s", other, src, dst));
            } else {
                continue;
            }
        }

        Logging.trace("TypeFlowGraph", String.format("TypeFlowGraph_%s Merge with %s", shortUUID, other));
    }


    public List<Set<T>> getConnectedComponents() {
        ConnectivityInspector<T, TypeFlowEdge> inspector = new ConnectivityInspector<>(graph);
        return inspector.connectedSets();
    }

    public StrongConnectivityAlgorithm<T, TypeFlowEdge> getStrongConnectedComponentsAlg() {
        return new KosarajuStrongConnectivityInspector<>(graph);
    }

    public boolean rebuildPathManager() {
        if (getNumNodes() <= 1) {
            return false;
        }
        this.pathManager = new TypeFlowPathManager<T>(this);
        this.pathManager.initialize();
        return true;
    }

    public String toGraphviz() {
        StringBuilder builder = new StringBuilder();
        builder.append("digraph TypeFlowGraph_").append(shortUUID).append(" {\n");
        for (TypeFlowEdge edge : graph.edgeSet()) {
            T src = graph.getEdgeSource(edge);
            T dst = graph.getEdgeTarget(edge);
            builder.append("  \"").append(src).append("\" -> \"").append(dst)
                    .append("\" [label=\"").append(edge.getType()).append("\"];\n");
        }
        builder.append("}");
        return builder.toString();
    }

    /**
     * Write the partial TFG for a given NMAE node into one graphviz file.
     * @param node The node to dump the TFG for
     * @param maxDepth Max graph edge depth around the node
     */
    public String toPartialGraphviz(T node, int maxDepth) {
        if (!graph.containsVertex(node)) {
            return "digraph Empty {\n}";
        }

        Set<TypeFlowEdge> includedEdges = new HashSet<>();

        // BFS to find nodes within maxDepth
        Map<T, Integer> distanceMap = new HashMap<>();
        Queue<T> queue = new LinkedList<>();

        // Start with the given node
        queue.add(node);
        distanceMap.put(node, 0);

        // Process outgoing edges (forward direction)
        while (!queue.isEmpty()) {
            T current = queue.poll();
            int currentDistance = distanceMap.get(current);

            if (currentDistance < maxDepth) {
                // Process outgoing edges
                for (TypeFlowEdge edge : graph.outgoingEdgesOf(current)) {
                    T target = graph.getEdgeTarget(edge);
                    if (!distanceMap.containsKey(target) || distanceMap.get(target) > currentDistance + 1) {
                        distanceMap.put(target, currentDistance + 1);
                        includedEdges.add(edge);
                        queue.add(target);
                    } else {
                        includedEdges.add(edge);
                    }
                }
            }
        }

        // Reset for backward traversal
        queue.clear();
        queue.add(node);
        Map<T, Integer> reverseDistanceMap = new HashMap<>();
        reverseDistanceMap.put(node, 0);

        // Process incoming edges (backward direction)
        while (!queue.isEmpty()) {
            T current = queue.poll();
            int currentDistance = reverseDistanceMap.get(current);

            if (currentDistance < maxDepth) {
                // Process incoming edges
                for (TypeFlowEdge edge : graph.incomingEdgesOf(current)) {
                    T source = graph.getEdgeSource(edge);
                    if (!reverseDistanceMap.containsKey(source) || reverseDistanceMap.get(source) > currentDistance + 1) {
                        reverseDistanceMap.put(source, currentDistance + 1);
                        includedEdges.add(edge);
                        queue.add(source);
                    } else {
                        includedEdges.add(edge);
                    }
                }
            }
        }

        // Generate graphviz representation
        StringBuilder builder = new StringBuilder();
        builder.append("digraph Partial_TypeFlowGraph_").append(shortUUID).append(" {\n");

        // Highlight the center node
        builder.append("  \"").append(node).append("\" [style=filled, fillcolor=lightblue];\n");

        // Add all edges
        for (TypeFlowEdge edge : includedEdges) {
            T src = graph.getEdgeSource(edge);
            T dst = graph.getEdgeTarget(edge);
            builder.append("  \"").append(src).append("\" -> \"").append(dst)
                    .append("\" [label=\"").append(edge.getType()).append("\"];\n");
        }

        builder.append("}");
        return builder.toString();
    }

    public TypeFlowGraph<T> createCopy() {
        Logging.trace("TypeFlowGraph", "Create copy of " + this);
        TypeFlowGraph<T> copy = new TypeFlowGraph<>();
        Graphs.addGraph(copy.graph, this.graph);
        return copy;
    }

    @Override
    public String toString() {
        return "TypeFlowGraph_" + shortUUID;
    }
}
