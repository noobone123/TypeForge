package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr;
import blueprint.utils.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

public class TypeAliasManager<T> {
    private final Set<TypeAliasGraph<T>> graphs;
    private final Map<T, TypeAliasGraph<T>> exprToGraph;

    public TypeAliasManager() {
        this.graphs = new HashSet<>();
        this.exprToGraph = new HashMap<>();
    }

    public void addEdge(T from, T to, TypeAliasGraph.EdgeType type) {
        TypeAliasGraph<T> fromGraph = exprToGraph.get(from);
        TypeAliasGraph<T> toGraph = exprToGraph.get(to);
        if (fromGraph == null && toGraph == null) {
            TypeAliasGraph<T> newGraph = new TypeAliasGraph<T>();
            newGraph.addEdge(from, to, type);
            graphs.add(newGraph);
            exprToGraph.put(from, newGraph);
            exprToGraph.put(to, newGraph);
        } else if (fromGraph == null) {
            toGraph.addEdge(from, to, type);
            exprToGraph.put(from, toGraph);
        } else if (toGraph == null) {
            fromGraph.addEdge(from, to, type);
            exprToGraph.put(to, fromGraph);
        } else if (fromGraph != toGraph) {
            mergeGraphs(fromGraph, toGraph);
            fromGraph.addEdge(from, to, type); // `mergeGraphs` should be called before `addEdge`
        } else {
            // fromGraph == toGraph
            fromGraph.addEdge(from, to, type);
        }
    }

    /**
     * Merge graph2 into graph1 and remove graph2 from the manager
     * @param graph1 the graph to merge into
     * @param graph2 the graph to merge
     */
    public void mergeGraphs(TypeAliasGraph<T> graph1, TypeAliasGraph<T> graph2) {
        for (var node: graph2.getNodes()) {
            exprToGraph.put(node, graph1);
        }

        // merge nodes
        graph1.getNodes().addAll(graph2.getNodes());

        // merge edges
        for (var entry: graph2.getAdjMap().entrySet()) {
            T src = entry.getKey();
            Map<T, TypeAliasGraph.EdgeType> existingEdges = graph1.getAdjMap().computeIfAbsent(src, k -> new HashMap<>());
            for (var edge: entry.getValue().entrySet()) {
                T dst = edge.getKey();
                var edgeType = edge.getValue();
                if (existingEdges.containsKey(dst) && existingEdges.get(dst) != edgeType) {
                    var oldEdgeType = existingEdges.get(dst);
                    Logging.warn("TypeAliasManager", String.format("Conflict edge type: %s --%s---> %s, %s --%s---> %s", src, oldEdgeType, dst, src, edgeType, dst));
                } else {
                    existingEdges.put(dst, edgeType);
                }
            }
        }

        graphs.remove(graph2);
        Logging.info("TypeAliasManager", String.format("Merge TypeAliasGraph: %s <-- %s", graph1, graph2));
    }


    public void removeNode(T node) {
        var graph = exprToGraph.get(node);
        if (graph != null) {
            graph.removeNode(node);
            if (graph.getConnectedComponents().size() > 1) {
                Logging.debug("TypeAliasManager", String.format("Split graph %s", graph));
                splitGraph(graph);
            }
        }
    }

    private void splitGraph(TypeAliasGraph<T> graph) {
        Set<TypeAliasGraph<T>> components = graph.getConnectedComponents();
        if (components.size() > 1) {
            graphs.remove(graph);
            for (var component: components) {
                graphs.add(component);
                for (var node: component.getNodes()) {
                    exprToGraph.put(node, component);
                }
            }
        }
    }

    public TypeAliasGraph<T> getTypeAliasGraph(T node) {
        return exprToGraph.get(node);
    }

    public Set<TypeAliasGraph<T>> getGraphs() {
        return graphs;
    }

    /**
     * If a graph has no symbol expressions in the given interested set, remove it from the manager
     * @param interested the set of symbol expressions which constraints are meaningful (possibly composite data type)
     */
    public void removeRedundantGraphs(Set<SymbolExpr> interested) {
        Set<TypeAliasGraph<T>> toRemove = new HashSet<>();
        for (var graph: graphs) {
            boolean hasInterestedNode = false;
            for (var node: graph.getNodes()) {
                if (node instanceof SymbolExpr expr && interested.contains(expr)) {
                    hasInterestedNode = true;
                    break;
                }
            }
            if (!hasInterestedNode) {
                Logging.debug("TypeAliasManager", String.format("Remove redundant graph %s", graph));
                toRemove.add(graph);
            }
        }

        for (var graph: toRemove) {
            graphs.remove(graph);
            for (var node: graph.getNodes()) {
                exprToGraph.remove(node);
            }
        }
    }


    public void dump(File outputDir) throws IOException {
        File metadataFile = new File(outputDir, "TypeAliasManager.json");

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        Map<String, Object> metadata = new HashMap<>();
        Map<String, String> exprToGraphID = new HashMap<>();
        List<String> graphIDs = new ArrayList<>();

        for (var entry: exprToGraph.entrySet()) {
            exprToGraphID.put(entry.getKey().toString(), entry.getValue().toString());
        }
        for (var graph: graphs) {
            graphIDs.add("TypeAliasGraph_" + graph.getShortUUID());
        }
        metadata.put("graphs", graphIDs);
        metadata.put("exprToGraph", exprToGraphID);
        mapper.writeValue(metadataFile, metadata);

        if (graphs.size() != exprToGraph.values().stream().distinct().count()) {
            Logging.error("TypeAliasManager", "Graphs and exprToGraph are inconsistent");
            System.exit(1);
        }

        for (var graph: graphs) {
            String graphName = "TypeAliasGraph_" + graph.getShortUUID();
            File graphFile = new File(outputDir, graphName + ".dot");
            Files.write(graphFile.toPath(), graph.toGraphviz().getBytes());
        }
    }
}
