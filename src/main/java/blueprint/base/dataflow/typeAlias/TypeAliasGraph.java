package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import org.jgrapht.Graph;
import org.jgrapht.alg.connectivity.ConnectivityInspector;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.Graphs;

import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;

import java.util.*;

public class TypeAliasGraph<T> {
    public enum EdgeType {
        CALL,
        RETURN,
        DATAFLOW,
        REFERENCE,
        INDIRECT,
        MEMALIAS,
    }

    public static class TypeAliasEdge extends DefaultEdge {
        private final EdgeType type;

        public TypeAliasEdge(EdgeType type) {
            this.type = type;
        }

        public EdgeType getType() {
            return type;
        }

        @Override
        public String toString() {
            return type.toString();
        }
    }

    private final Graph<T, TypeAliasEdge> graph;
    private final UUID uuid;
    private final String shortUUID;

    public TypeAliasPathManager<T> pathManager;

    public TypeAliasGraph() {
        graph = new DefaultDirectedGraph<>(TypeAliasEdge.class);
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);

        pathManager = new TypeAliasPathManager<T>(this);

        Logging.debug("TypeAliasGraph", String.format("Create TypeAliasGraph_%s", shortUUID));
    }

    public String getShortUUID() {
        return shortUUID;
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        graph.addVertex(src);
        graph.addVertex(dst);
        graph.addEdge(src, dst, new TypeAliasEdge(edgeType));
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        graph.removeEdge(src, dst);
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Remove edge: %s ---> %s", shortUUID, src, dst));
    }

    public void removeNode(T node) {
        graph.removeVertex(node);
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Remove node: %s", shortUUID, node));
    }

    public int getNumNodes() {
        return graph.vertexSet().size();
    }

    public Set<T> getNodes() {
        return graph.vertexSet();
    }

    public Graph<T, TypeAliasEdge> getGraph() {
        return graph;
    }

    public void mergeGraph(TypeAliasGraph<T> other) {
        for (T vertex: other.getNodes()) {
            graph.addVertex(vertex);
        }

        Set<TypeAliasEdge> edges = other.getGraph().edgeSet();
        for (TypeAliasEdge edge: edges) {
            T src = other.getGraph().getEdgeSource(edge);
            T dst = other.getGraph().getEdgeTarget(edge);
            var EdgeType = edge.getType();

            TypeAliasEdge existingEdge = graph.getEdge(src, dst);
            if (existingEdge == null) {
                graph.addEdge(src, dst, new TypeAliasEdge(EdgeType));
            } else if (existingEdge.getType() != EdgeType) {
                Logging.warn("TypeAliasGraph", String.format("%s Merge conflict: %s ---> %s", other, src, dst));
            } else {
                continue;
            }
        }

        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Merge with %s", shortUUID, other));
    }


    public void removeAllEdgesOfNode(T node) {
        Set<TypeAliasEdge> edges = graph.edgesOf(node);
        for (TypeAliasEdge edge: edges) {
            T src = graph.getEdgeSource(edge);
            T dst = graph.getEdgeTarget(edge);
            graph.removeEdge(src, dst);
        }
    }

    public List<Set<T>> getConnectedComponents() {
        ConnectivityInspector<T, TypeAliasEdge> inspector = new ConnectivityInspector<>(graph);
        var result = inspector.connectedSets();

        return result;
    }

    public String toGraphviz() {
        StringBuilder builder = new StringBuilder();
        builder.append("digraph TypeAliasGraph_").append(shortUUID).append(" {\n");
        for (TypeAliasEdge edge : graph.edgeSet()) {
            T src = graph.getEdgeSource(edge);
            T dst = graph.getEdgeTarget(edge);
            builder.append("  \"").append(src).append("\" -> \"").append(dst)
                    .append("\" [label=\"").append(edge.getType()).append("\"];\n");
        }
        builder.append("}");
        return builder.toString();
    }

    public TypeAliasGraph<T> createCopy() {
        Logging.debug("TypeAliasGraph", "Create copy of " + this);
        TypeAliasGraph<T> copy = new TypeAliasGraph<>();
        Graphs.addGraph(copy.graph, this.graph);
        return copy;
    }

    @Override
    public String toString() {
        return "TypeAliasGraph_" + shortUUID;
    }
}
