package blueprint.solver;

import blueprint.base.dataflow.SymbolExpr;
import blueprint.base.dataflow.constraints.PrimitiveTypeDescriptor;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Generator {
    public final Map<SymbolExpr, TypeConstraint> allConstraints;

    public Generator(Context solverCtx) {
        this.allConstraints = new HashMap<>(solverCtx.symExprToConstraints);
    }

    public void generateSkeleton() {
        allConstraints.forEach((symExpr, constraint) -> {
            buildSkeleton(constraint);
        });
    }

    public void buildSkeleton(TypeConstraint con) {
        con.accessOffsets.forEach((ap, offsets) -> {
            if (offsets.size() > 1) {
                for (var offset : offsets) {
                    // If one pcode Access Multiple fields, we should add a tag to the field
                    con.addFieldAttr(offset, TypeConstraint.Attribute.MULTI_ACCESS);
                }
            }
        });

        handleMultiReference(con);

        // TODO: parse and set ptr level
        // ...
    }

    /**
     * Sometimes one field may reference multiple constraints, For example:
     * If FuncA: *(a + 0x10) and FuncB: *(b + 0x10) has no direct data-flow relation,
     * but a and b has a direct data-flow relation, then Solver will create 2 constraints for a + 0x10 and b + 0x10
     * and these two constraints will be put into same offset when merging a and b.
     * However, we think these two constraints are actually the same type, so we should merge them here.
     */
    private void handleMultiReference(TypeConstraint constraint) {
        for (var entry: constraint.referenceTo.entrySet()) {
            if (entry.getValue().size() > 1) {
                Logging.info("Generator", String.format("Constraint_%s has multiple referenceTo at 0x%x", constraint.shortUUID, entry.getKey()));
                boolean shouldMerge = checkOffsetSize(constraint, entry.getKey(), Global.currentProgram.getDefaultPointerSize());
                if (!shouldMerge) { continue; }

                TypeConstraint newMergedConstraint = new TypeConstraint();
                Logging.debug("Generator", String.format("Created new merged constraint: Constraint_%s", newMergedConstraint.shortUUID));
                var toMerge = new HashSet<>(entry.getValue());
                for (var ref: toMerge) {
                    Logging.debug("Generator", String.format("Merging Constraint_%s to Constraint_%s", ref.shortUUID, newMergedConstraint.shortUUID));
                    newMergedConstraint.merge(ref);
                }

                // Updated into Context
                constraint.referenceTo.put(entry.getKey(), new HashSet<>(Set.of(newMergedConstraint)));
            }
        }
    }


    private boolean checkOffsetSize(TypeConstraint constraint, long offset, int wantedSize) {
        boolean result = true;
        for (var entry: constraint.fieldMap.get(offset).entrySet()) {
            if (entry.getKey() instanceof PrimitiveTypeDescriptor primType) {
                if (primType.getDataTypeSize() != wantedSize) {
                    result = false;
                    Logging.warn("Generator", String.format("Constraint_%s has different size at 0x%x: %s when handling multiReference.", constraint.shortUUID, offset, primType.getName()));
                    break;
                }
            }
        }
        return result;
    }



    public void dumpResults() {
        String workingDir = System.getProperty("user.dir");
        Logging.info("Generator", "Current working directory: " + workingDir);

        File outputDir = new File(System.getProperty("user.dir") + File.separator + "codes/blueprint/dummy");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        // dump constraints to JSON file
        File outputFile = new File(outputDir, "constraints.json");
        var mapper = new ObjectMapper();
        var root = mapper.createObjectNode();
        allConstraints.forEach((symExpr, constraint) -> {
            root.set("Constraint_" + constraint.shortUUID, constraint.getJsonObj(mapper));
        });

        // dump metadata to JSON file
        File outputFile2 = new File(outputDir, "metadata.json");
        var mapper2 = new ObjectMapper();
        var root2 = mapper2.createObjectNode();
        allConstraints.forEach((symExpr, constraint) -> {
            var prefix = symExpr.prefix;
            var prefixNode = (ObjectNode) root2.get(prefix);
            if (prefixNode == null) {
                prefixNode = mapper2.createObjectNode();
                root2.set(prefix, prefixNode);
            }
            prefixNode.put(symExpr.getRepresentation(), "Constraint_" + constraint.shortUUID);
        });

        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, root);
            Logging.info("Generator", "Constraints dumped to " + outputFile.getPath());

            mapper2.writerWithDefaultPrettyPrinter().writeValue(outputFile2, root2);
            Logging.info("Generator", "Metadata dumped to " + outputFile2.getPath());

        } catch (IOException e) {
            Logging.error("Generator", "Error writing JSON to file" + e.getMessage());
        }
    }

}
