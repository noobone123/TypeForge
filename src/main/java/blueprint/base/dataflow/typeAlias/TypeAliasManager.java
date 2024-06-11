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
            exprToGraph.put(from, newGraph);
            exprToGraph.put(to, newGraph);
            graphs.add(newGraph);
        } else if (fromGraph == null) {
            toGraph.addEdge(from, to, type);
            exprToGraph.put(from, toGraph);
        } else if (toGraph == null) {
            fromGraph.addEdge(from, to, type);
            exprToGraph.put(to, fromGraph);
        } else if (fromGraph != toGraph) {
            mergeGraphs(fromGraph, toGraph);
            fromGraph.addEdge(from, to, type);
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
        for (var node: graph2.getAdjList().keySet()) {
            exprToGraph.put(node, graph1);
        }

        graph1.getAdjList().putAll(graph2.getAdjList());
        graphs.remove(graph2);
        Logging.info("TypeAliasManager", String.format("Merge %s into %s", graph2, graph1));
    }


    public void removeNode(T node) {
        var graph = exprToGraph.get(node);
        if (graph != null) {
            graph.removeNode(node);
            splitGraph(graph);
        }
    }

    private void splitGraph(TypeAliasGraph<T> graph) {
        Set<TypeAliasGraph<T>> components = graph.getConnectedComponents();
        if (components.size() > 1) {
            graphs.remove(graph);
            for (var component: components) {
                graphs.add(component);
                for (var node: component.getAdjList().keySet()) {
                    exprToGraph.put(node, component);
                }
            }
            graphs.remove(graph);
        }
    }

    public TypeAliasGraph<T> getTypeAliasGraph(T node) {
        return exprToGraph.get(node);
    }

    /**
     * If a graph has no symbol expressions in the given set, remove it from the manager
     * @param memExprs the set of memory access symbol expressions
     */
    public void removeRedundantGraphs(Set<SymbolExpr> memExprs) {
        Set<SymbolExpr> memExprRootSymbols = new HashSet<>();
        for (var expr: memExprs) {
            memExprRootSymbols.add(expr.getRootSymExpr());
        }

        Set<TypeAliasGraph<T>> toRemove = new HashSet<>();
        for (var graph: graphs) {
            boolean hasMemExpr = false;
            for (var node: graph.getNodes()) {
                if (node instanceof SymbolExpr expr && memExprRootSymbols.contains(expr)) {
                    hasMemExpr = true;
                    break;
                }
            }
            if (!hasMemExpr) {
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


    public void dump(String dirName) throws IOException {
        if (!new File(dirName).exists()) {
            new File(dirName).mkdirs();
        } else {
            // remove directory and recreate
            File dir = new File(dirName);
            for (File file: dir.listFiles()) {
                if (!file.delete()) {
                    throw new IOException("Failed to delete file: " + file);
                }
            }
        }

        File metadataFile = new File(dirName, "metadata.json");

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

        assert graphs.size() == exprToGraph.values().stream().distinct().count();

        for (var graph: graphs) {
            String graphName = "TypeAliasGraph_" + graph.getShortUUID();
            File graphFile = new File(dirName, graphName + ".dot");
            Files.write(graphFile.toPath(), graph.toGraphviz().getBytes());
        }
    }
}
