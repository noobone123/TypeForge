package blueprint.base.dataflow.typeAlias;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;
import org.jgrapht.GraphPath;

import java.util.*;

public class TypeAliasPath<T> {
    public GraphPath<T, TypeAliasGraph.TypeAliasEdge> path;
    public List<T> nodes;
    public List<TypeConstraint> backwardMergedConstraints;
    public List<TypeConstraint> forwardMergedConstraints;
    public List<TypeAliasGraph.TypeAliasEdge> edges;
    public TypeConstraint finalConstraint;

    public TypeAliasPath(GraphPath<T, TypeAliasGraph.TypeAliasEdge> path) {
        this.path = path;

        // update nodes;
        this.nodes = path.getVertexList();
        this.edges = path.getEdgeList();

        this.backwardMergedConstraints = new ArrayList<>();
        this.forwardMergedConstraints = new ArrayList<>();
    }

    public void tryMergeByPath(SymbolExprManager exprManager) {
        for (int i = 0; i < nodes.size(); i++) {
            T node = nodes.get(i);
            TypeConstraint curMergedCon;
            SymbolExpr curExpr = (SymbolExpr) node;
            TypeConstraint curExprCon = exprManager.getConstraint(curExpr);

            if (curExprCon == null) {
                Logging.warn("TypeAliasPath", String.format("Cannot find constraint for %s in path", node));
                curMergedCon = new TypeConstraint();
                Logging.info("TypeAliasPath", String.format("Created new Constraint %s for %s in path", curMergedCon, curExpr));
            } else {
                curMergedCon = new TypeConstraint(curExprCon);
                Logging.info("TypeAliasPath", String.format("Created new Constraint %s for %s in path", curMergedCon, curExpr));
                // If Current Expr is fieldAccessExpr, try to merge its memAliasExpr's TypeConstraint
                if (curExpr.isDereference()) {
                    Logging.info("TypeAliasPath", String.format("Try to merge memAlias into %s", curMergedCon));
                    var mayMemAliases = exprManager.getMayMemAliases(curExpr);
                    for (var alias: mayMemAliases) {
                        if (alias == curExpr) {
                            continue;
                        }
                        var aliasCon = exprManager.getConstraint(alias);
                        if (aliasCon == null) {
                            continue;
                        }
                        var noConflict = curMergedCon.tryMerge(aliasCon);
                        if (!noConflict) {
                            Logging.warn("TypeAliasPath", String.format("Conflict when merging TypeConstraints in memAlias for %s and %s", curExpr, alias));
                            continue;
                        }
                    }
                }
            }

            // Merge backward constraints in the path
            if (i > 0) {
                var prevMergedCon = backwardMergedConstraints.get(i - 1);
                Logging.info("TypeAliasPath", String.format("Try to merge previous into current: %s -> %s", prevMergedCon, curMergedCon));
                Logging.info("TypeAliasPath", prevMergedCon.dumpLayout());
                Logging.info("TypeAliasPath", curMergedCon.dumpLayout());
                if (prevMergedCon.isEmpty()) {
                    backwardMergedConstraints.add(curMergedCon);
                    continue;
                } else if (curMergedCon.isEmpty()) {
                    backwardMergedConstraints.add(prevMergedCon);
                    continue;
                } else {
                    var noConflict = curMergedCon.tryMerge(prevMergedCon);
                    if (noConflict) {
                        backwardMergedConstraints.add(curMergedCon);
                        continue;
                    }
                    // TODO: Important, if there is a conflict when merging along the path, we should mark the node and split the path
                    else {
                        Logging.warn("TypeAliasPath", String.format("Conflict when merging TypeConstraints in path for %s", curExpr));
                        return;
                    }
                }
            } else {
                backwardMergedConstraints.add(curMergedCon);
            }
        }
    }


    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(nodes.get(0));
        for (int i = 0; i < edges.size(); i++) {
            builder.append(String.format(" --- %s ---> ", edges.get(i).getType()));
            if (i + 1 < nodes.size()) {
                builder.append(nodes.get(i + 1));
            }
        }
        return builder.toString();
    }
}
