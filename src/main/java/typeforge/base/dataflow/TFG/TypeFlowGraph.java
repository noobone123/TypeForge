package typeforge.base.dataflow.TFG;

import org.jgrapht.Graph;
import org.jgrapht.alg.connectivity.ConnectivityInspector;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.Graphs;

import typeforge.utils.Logging;

import java.util.*;

public class TypeFlowGraph<T> {
    public enum EdgeType {
        CALL,
        RETURN,
        DATAFLOW,
        REFERENCE,
        ALIAS,
    }

    public static class TypeRelationEdge extends DefaultEdge {
        private final EdgeType type;

        public TypeRelationEdge(EdgeType type) {
            this.type = type;
        }

        public EdgeType getType() {
            return type;
        }

        @Override
        public int hashCode() {
            return Objects.hash(this.getSource(), this.getTarget(), type);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            TypeRelationEdge other = (TypeRelationEdge) obj;
            return this.getSource().equals(other.getSource()) && this.getTarget().equals(other.getTarget()) && this.type == other.type;
        }

        @Override
        public String toString() {
            var source = this.getSource();
            var target = this.getTarget();
            return String.format("%s ---%s---> %s", source, type, target);
        }
    }

    private final Graph<T, TypeRelationEdge> graph;
    private final UUID uuid;
    private final String shortUUID;

    public TypeRelationPathManager<T> pathManager;

    public TypeFlowGraph() {
        graph = new DefaultDirectedGraph<>(TypeRelationEdge.class);
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        pathManager = new TypeRelationPathManager<T>(this);

        Logging.debug("TypeRelationGraph", String.format("Create TypeRelationGraph_%s", shortUUID));
    }

    public String getShortUUID() {
        return shortUUID;
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        graph.addVertex(src);
        graph.addVertex(dst);
        graph.addEdge(src, dst, new TypeRelationEdge(edgeType));
        Logging.debug("TypeRelationGraph", String.format("TypeRelationGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        graph.removeEdge(src, dst);
        Logging.debug("TypeRelationGraph", String.format("TypeRelationGraph_%s Remove edge: %s ---> %s", shortUUID, src, dst));
    }

    public void removeNode(T node) {
        graph.removeVertex(node);
        Logging.debug("TypeRelationGraph", String.format("TypeRelationGraph_%s Remove node: %s", shortUUID, node));
    }

    public int getNumNodes() {
        return graph.vertexSet().size();
    }

    public Set<T> getNodes() {
        return graph.vertexSet();
    }

    public Graph<T, TypeRelationEdge> getGraph() {
        return graph;
    }

    public void mergeGraph(TypeFlowGraph<T> other) {
        for (T vertex: other.getNodes()) {
            graph.addVertex(vertex);
        }

        Set<TypeRelationEdge> edges = other.getGraph().edgeSet();
        for (TypeRelationEdge edge: edges) {
            T src = other.getGraph().getEdgeSource(edge);
            T dst = other.getGraph().getEdgeTarget(edge);
            var EdgeType = edge.getType();

            TypeRelationEdge existingEdge = graph.getEdge(src, dst);
            if (existingEdge == null) {
                graph.addEdge(src, dst, new TypeRelationEdge(EdgeType));
            } else if (existingEdge.getType() != EdgeType) {
                Logging.warn("TypeRelationGraph", String.format("%s Merge conflict: %s ---> %s", other, src, dst));
            } else {
                continue;
            }
        }

        Logging.debug("TypeRelationGraph", String.format("TypeRelationGraph_%s Merge with %s", shortUUID, other));
    }


    public List<Set<T>> getConnectedComponents() {
        ConnectivityInspector<T, TypeRelationEdge> inspector = new ConnectivityInspector<>(graph);
        var result = inspector.connectedSets();

        return result;
    }

    public boolean rebuildPathManager() {
        if (getNumNodes() <= 1) {
            return false;
        }
        this.pathManager = new TypeRelationPathManager<T>(this);
        this.pathManager.build();
        return true;
    }

    public String toGraphviz() {
        StringBuilder builder = new StringBuilder();
        builder.append("digraph TypeRelationGraph_").append(shortUUID).append(" {\n");
        for (TypeRelationEdge edge : graph.edgeSet()) {
            T src = graph.getEdgeSource(edge);
            T dst = graph.getEdgeTarget(edge);
            builder.append("  \"").append(src).append("\" -> \"").append(dst)
                    .append("\" [label=\"").append(edge.getType()).append("\"];\n");
        }
        builder.append("}");
        return builder.toString();
    }

    public TypeFlowGraph<T> createCopy() {
        Logging.debug("TypeRelationGraph", "Create copy of " + this);
        TypeFlowGraph<T> copy = new TypeFlowGraph<>();
        Graphs.addGraph(copy.graph, this.graph);
        return copy;
    }

    @Override
    public String toString() {
        return "TypeRelationGraph_" + shortUUID;
    }
}
