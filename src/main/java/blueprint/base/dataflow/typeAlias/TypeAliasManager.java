package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.utils.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;

import java.io.File;
import java.io.FileWriter;
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
            for (var node: toGraph.getNodes()) {
                exprToGraph.put(node, fromGraph);
            }
            fromGraph.mergeGraph(toGraph);
            graphs.remove(toGraph);
            fromGraph.addEdge(from, to, type); // `mergeGraphs` should be called before `addEdge`
        } else {
            // fromGraph == toGraph
            fromGraph.addEdge(from, to, type);
        }
    }

    public boolean hasEdge(T from, T to) {
        TypeAliasGraph<T> fromGraph = exprToGraph.get(from);
        TypeAliasGraph<T> toGraph = exprToGraph.get(to);
        return fromGraph != null && fromGraph == toGraph;
    }


    public TypeAliasGraph<T> getTypeAliasGraph(T node) {
        return exprToGraph.get(node);
    }

    public Set<TypeAliasGraph<T>> getGraphs() {
        return graphs;
    }

    /**
     * If a graph has no nodes with fields, it is redundant and should be removed.
     * @param baseToFieldsMap A map from base to its fields
     */
    public void removeRedundantGraphs(Map<SymbolExpr, TreeMap<Long, Set<SymbolExpr>>> baseToFieldsMap) {
        Set<TypeAliasGraph<T>> toRemove = new HashSet<>();
        for (var graph: graphs) {
            boolean hasInterestedNode = false;
            for (var node: graph.getNodes()) {
                if (node instanceof SymbolExpr expr && baseToFieldsMap.containsKey(expr) && !baseToFieldsMap.get(expr).isEmpty()) {
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

    public void dumpGraphMeta(File outputDir) throws IOException {
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


    public void dumpEntryToExitPaths(File outputDir) {
        File textFile = new File(outputDir, "EntryToExitPaths.txt");

        try (FileWriter writer = new FileWriter(textFile)) {
            for (var graph: graphs) {
                graph.pathManager.dump(writer);
                writer.write("\n ----------------------------------------------------------- \n");
            }
        } catch (Exception e) {
            Logging.error("TypeAliasManager", "Failed to write entry to exit paths to file" + e);
            e.printStackTrace();
            System.exit(1);
        }
    }
}
