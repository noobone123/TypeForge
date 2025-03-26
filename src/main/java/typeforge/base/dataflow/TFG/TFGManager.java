package typeforge.base.dataflow.TFG;

import typeforge.base.dataflow.expression.NMAE;
import typeforge.utils.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

public class TFGManager {
    private final Set<TypeFlowGraph<NMAE>> graphs;
    private final Map<NMAE, TypeFlowGraph<NMAE>> exprToGraph;

    public TFGManager() {
        this.graphs = new HashSet<>();
        this.exprToGraph = new HashMap<>();
    }

    public void addEdge(NMAE from, NMAE to, TypeFlowGraph.EdgeType type) {
        TypeFlowGraph<NMAE> fromGraph = exprToGraph.get(from);
        TypeFlowGraph<NMAE> toGraph = exprToGraph.get(to);
        if (fromGraph == null && toGraph == null) {
            TypeFlowGraph<NMAE> newGraph = new TypeFlowGraph<NMAE>();
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

    public boolean hasEdge(NMAE from, NMAE to) {
        TypeFlowGraph<NMAE> fromGraph = exprToGraph.get(from);
        TypeFlowGraph<NMAE> toGraph = exprToGraph.get(to);
        return fromGraph != null && fromGraph == toGraph;
    }


    public TypeFlowGraph<NMAE> getTypeRelationGraph(NMAE node) {
        return exprToGraph.get(node);
    }

    public Set<TypeFlowGraph<NMAE>> getGraphs() {
        return graphs;
    }

    public void buildAllPathManagers() {
        for (var graph: graphs) {
            if (graph.getNumNodes() > 1) {
                Logging.debug("InterContext", String.format("Handing type alias graph %s", graph));
                graph.pathManager.build();
            }
        }
    }


    /**
     * If a graph has no nodes with fields, it is redundant and should be removed.
     * @param baseToFieldsMap A map from base to its fields
     */
    public void removeRedundantGraphs(Map<NMAE, TreeMap<Long, Set<NMAE>>> baseToFieldsMap) {
        Set<TypeFlowGraph<NMAE>> toRemove = new HashSet<>();
        for (var graph: graphs) {
            boolean hasInterestedNode = false;
            for (var node: graph.getNodes()) {
                if (baseToFieldsMap.containsKey(node) && !baseToFieldsMap.get(node).isEmpty()) {
                    hasInterestedNode = true;
                    break;
                }
            }
            if (!hasInterestedNode) {
                Logging.trace("TypeRelationManager", String.format("Remove redundant graph %s", graph));
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

    /**
     * Statistics Node and Edge information for TFGs
     */
    public void TFGStatistics() {
        var totalNodes = 0;
        var totalEdges = 0;
        var TFGnum = 0;

        Logging.info("TFGManager", "TFG Statistics:");
    }


    public void dumpTRG(File outputDir) throws IOException {
        File metadataFile = new File(outputDir, "TypeRelationManager.json");

        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        Map<String, Object> metadata = new HashMap<>();
        Map<String, String> exprToGraphID = new HashMap<>();
        List<String> graphIDs = new ArrayList<>();

        for (var entry: exprToGraph.entrySet()) {
            exprToGraphID.put(entry.getKey().toString(), entry.getValue().toString());
        }
        for (var graph: graphs) {
            graphIDs.add("TypeRelationGraph_" + graph.getShortUUID());
        }
        metadata.put("graphs", graphIDs);
        metadata.put("exprToGraph", exprToGraphID);
        mapper.writeValue(metadataFile, metadata);

        if (graphs.size() != exprToGraph.values().stream().distinct().count()) {
            Logging.error("TypeRelationManager", "Graphs and exprToGraph are inconsistent");
            System.exit(1);
        }

        for (var graph: graphs) {
            String graphName = "TypeRelationGraph_" + graph.getShortUUID();
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
            Logging.error("TypeRelationManager", "Failed to write entry to exit paths to file" + e);
            e.printStackTrace();
            System.exit(1);
        }
    }
}
