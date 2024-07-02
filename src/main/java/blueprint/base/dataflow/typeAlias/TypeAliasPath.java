package blueprint.base.dataflow.typeAlias;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;
import org.jgrapht.GraphPath;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TypeAliasPath<T> {
    public GraphPath<T, TypeAliasGraph.TypeAliasEdge> path;
    public List<T> nodes;
    public List<TypeAliasGraph.TypeAliasEdge> edges;
    public Map<T, TypeConstraint> backwardConstraints;
    public Map<T, TypeConstraint> forwardConstraints;
    public TypeConstraint finalConstraint;

    public TypeAliasPath(GraphPath<T, TypeAliasGraph.TypeAliasEdge> path) {
        this.path = path;

        // update nodes;
        this.nodes = path.getVertexList();
        this.edges = path.getEdgeList();

        this.backwardConstraints = new HashMap<>();
        this.forwardConstraints = new HashMap<>();
    }

    public void tryMergeByPath(SymbolExprManager exprManager) {
        for (int i = 0; i < nodes.size() - 1; i++) {
            T node = nodes.get(i);
            SymbolExpr expr = (SymbolExpr) node;
            TypeConstraint constraint = exprManager.getConstraint(expr);
            if (constraint == null) {
                Logging.warn("TypeAliasPath", String.format("Cannot find constraint for %s in path", node));
                continue;
            }

            if (expr.isDereference()) {
                var mayMemAliases = exprManager.getMayMemAliases(expr);
                // TODO: merge all TypeConstraints within 1 path, and then dump TypeConstraints into file ...
//                for (var alias: mayMemAliases) {
//                    var aliasCon = exprManager.getConstraint(alias);
//                    var conflict = constraint.tryMerge(aliasCon);
//                    if (conflict) {
//                        continue;
//                    }
//                }
            }

//            if (i > 0) {
//                var prevNode = nodes.get(i - 1);
//                var prevCon = backwardConstraints.get(prevNode);
//                var conflict = prevCon.tryMerge(constraint);
//                if (conflict) {
//                    continue;
//                }
//            }
            backwardConstraints.put(node, constraint);
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
