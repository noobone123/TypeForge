package blueprint.utils;

import blueprint.base.DataTypeNode;
import blueprint.base.SDGraph;
import blueprint.base.NodeBase;
import ghidra.program.model.data.DataType;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;

public class Helper {

    /**
     * Dump the SDGraph to a dot file
     */
    public static void dumpSDGraph(SDGraph sdg, String filename) {
        StringBuilder dotBuilder = new StringBuilder();

        Set<NodeBase<DataType>> allNodes = sdg.getAllNodes();
        Set<SDGraph.SDEdge> allEdges = sdg.getAllEdges();

        dotBuilder.append("digraph SDGraph {\n");

        // traverse all nodes
        for (var node : allNodes) {
            if (node instanceof DataTypeNode dtn) {
                String nodeID = "node" + dtn.id;
                String nodeLabel = dtn.value.getName();
                dotBuilder.append(
                        String.format(
                                "%s [label=\"%s\"];\n",
                                nodeID,
                                nodeLabel
                        )
                );
            }
        }

        // traverse all edges
        for (var edge : allEdges) {
            String srcNodeID = "node" + edge.srcNode.id;
            String dstNodeID = "node" + edge.dstNode.id;
            String edgeType = edge.edgeType.toString();
            String edgeLabel = String.format("Offset %s: %s", Integer.toHexString(edge.offset), edgeType);
            dotBuilder.append(
                    String.format(
                            "%s -> %s [label=\"%s\"];\n",
                            srcNodeID,
                            dstNodeID,
                            edgeLabel
                    )
            );
        }

        dotBuilder.append("}\n");

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filename))) {
            writer.write(dotBuilder.toString());
        } catch (IOException e) {
            Logging.error("Failed to write to file: " + filename);
        }
    }
}
