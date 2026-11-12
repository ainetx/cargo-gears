extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_then;
use rustc_hir::attrs::lang_items::LangItem;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::{self as hir, Expr, ExprKind, MatchSource, Pat, PatKind, StmtKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{self, Ty, TypeckResults};
use rustc_span::Span;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects a PDP-compiled `AccessScope` that is awaited and then thrown
    /// away: bound to `_` or an `_`-prefixed name, dropped as a statement,
    /// matched as `Ok(_)`, or reduced to `.is_ok()` / `.is_err()`.
    ///
    /// ### Why is this bad?
    ///
    /// A PDP decision is usually *allow, constrained to a scope* (for example
    /// "only rows owned by the caller's tenant"). The scope is the only part of
    /// the decision that ties it to the resource being touched; discarding it
    /// turns the check into "is the caller allowed to do this to *something*",
    /// which is a cross-tenant authorization bypass whenever the target id comes
    /// from the request.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// // Bad - the decision is never applied to `input.parent_id`
    /// let _scope = self.authorize(ctx, CREATE, input.parent_id, None).await?;
    /// let parent = repo.find_by_id(&AccessScope::allow_all(), input.parent_id).await?;
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let scope = self.authorize(ctx, CREATE, input.parent_id, None).await?;
    /// let parent = repo.find_by_id(&scope, input.parent_id).await?;
    /// ```
    ///
    /// ### Limitations
    ///
    /// Intra-procedural: a scope passed to a helper that ignores it, or a scope
    /// applied to the wrong entity, is not detected.
    #[doc = include_str!("de0709_discarded_access_scope/README.md")]
    pub DE0709_DISCARDED_ACCESS_SCOPE,
    Warn,
    "a PDP-compiled `AccessScope` is discarded instead of being applied (DE0709)"
}

/// `AccessScope`, matched by type name so every re-export resolves the same way.
pub(crate) fn is_access_scope(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    matches!(ty.peel_refs().kind(), ty::Adt(def, _) if cx.tcx.item_name(def.did()).as_str() == "AccessScope")
}

/// `AccessScope`, or a `Result` / `Option` whose payload is one.
pub(crate) fn carries_access_scope<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> bool {
    if is_access_scope(cx, ty) {
        return true;
    }
    let ty::Adt(def, args) = ty.peel_refs().kind() else {
        return false;
    };
    let is_wrapper = cx
        .tcx
        .is_diagnostic_item(rustc_span::sym::Result, def.did())
        || cx
            .tcx
            .is_diagnostic_item(rustc_span::sym::Option, def.did());
    is_wrapper
        && args
            .types()
            .next()
            .is_some_and(|payload| is_access_scope(cx, payload))
}

/// Span of an `.await` inside `expr` that yields a scope — the shape of every
/// PDP round-trip (`enforcer.access_scope_with(..).await`, `self.authorize(..).await`).
/// Synchronous constructors such as `AccessScope::allow_all()` never match.
pub(crate) fn awaited_scope<'tcx>(
    cx: &LateContext<'tcx>,
    typeck: &'tcx TypeckResults<'tcx>,
    expr: &'tcx Expr<'tcx>,
) -> Option<Span> {
    struct Finder<'a, 'tcx> {
        cx: &'a LateContext<'tcx>,
        typeck: &'tcx TypeckResults<'tcx>,
        found: Option<Span>,
    }
    impl<'tcx> hir::intravisit::Visitor<'tcx> for Finder<'_, 'tcx> {
        fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
            if self.found.is_some() {
                return;
            }
            if let ExprKind::Match(_, _, MatchSource::AwaitDesugar) = expr.kind
                && let Some(ty) = self.typeck.expr_ty_opt(expr)
                && carries_access_scope(self.cx, ty)
            {
                self.found = Some(expr.span);
                return;
            }
            hir::intravisit::walk_expr(self, expr);
        }
    }
    let mut finder = Finder {
        cx,
        typeck,
        found: None,
    };
    hir::intravisit::Visitor::visit_expr(&mut finder, expr);
    finder.found
}

fn is_discarding_binding(pat: &Pat<'_>) -> bool {
    match pat.kind {
        PatKind::Wild => true,
        PatKind::Binding(_, _, ident, None) => ident.as_str().starts_with('_'),
        _ => false,
    }
}

/// `Ok(_)`, `Ok(_x)`, `Ok(..)`, `Some(_)` — a pattern that accepts the scope without binding it.
fn discards_payload(cx: &LateContext<'_>, pat: &Pat<'_>) -> bool {
    let PatKind::TupleStruct(ref qpath, fields, _) = pat.kind else {
        return false;
    };
    let Res::Def(DefKind::Ctor(..), ctor) = cx.qpath_res(qpath, pat.hir_id) else {
        return false;
    };
    let variant = Some(cx.tcx.parent(ctor));
    let lang = cx.tcx.lang_items();
    let is_ok_or_some =
        variant == lang.get(LangItem::ResultOk) || variant == lang.get(LangItem::OptionSome);
    is_ok_or_some && fields.iter().all(is_discarding_binding)
}

struct ScopeVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    typeck: &'tcx TypeckResults<'tcx>,
}

impl ScopeVisitor<'_, '_> {
    fn report(&self, span: Span, what: &str) {
        span_lint_and_then(
            self.cx,
            DE0709_DISCARDED_ACCESS_SCOPE,
            span,
            format!("PDP-compiled `AccessScope` is {what} (DE0709)"),
            |diag| {
                diag.help(
                    "apply the scope to the resource the request names (e.g. `repo.find_by_id(&scope, id)`), \
                     or check the id against it, instead of relying on the bare allow/deny",
                );
                diag.note(
                    "a PDP allow is usually constrained to the caller's own tenant/subtree; the scope is what ties it to the target",
                );
            },
        );
    }
}

impl<'tcx> hir::intravisit::Visitor<'tcx> for ScopeVisitor<'_, 'tcx> {
    fn visit_stmt(&mut self, stmt: &'tcx hir::Stmt<'tcx>) {
        match stmt.kind {
            StmtKind::Let(local)
                if let Some(init) = local.init
                    && is_discarding_binding(local.pat)
                    && carries_access_scope(self.cx, self.typeck.pat_ty(local.pat))
                    && awaited_scope(self.cx, self.typeck, init).is_some() =>
            {
                self.report(local.span, "bound to a discarded name");
            }
            StmtKind::Semi(expr)
                if self
                    .typeck
                    .expr_ty_opt(expr)
                    .is_some_and(|ty| carries_access_scope(self.cx, ty))
                    && awaited_scope(self.cx, self.typeck, expr).is_some() =>
            {
                self.report(stmt.span, "dropped as a statement");
            }
            _ => {}
        }
        hir::intravisit::walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        match expr.kind {
            ExprKind::Match(scrutinee, arms, MatchSource::Normal)
                if awaited_scope(self.cx, self.typeck, scrutinee).is_some() =>
            {
                for arm in arms {
                    if discards_payload(self.cx, arm.pat) {
                        self.report(arm.pat.span, "matched without being bound");
                    }
                }
            }
            ExprKind::Let(let_expr)
                if discards_payload(self.cx, let_expr.pat)
                    && awaited_scope(self.cx, self.typeck, let_expr.init).is_some() =>
            {
                self.report(let_expr.pat.span, "matched without being bound");
            }
            ExprKind::MethodCall(segment, receiver, [], _)
                if matches!(
                    segment.ident.as_str(),
                    "is_ok" | "is_err" | "is_some" | "is_none"
                ) && awaited_scope(self.cx, self.typeck, receiver).is_some() =>
            {
                self.report(expr.span, "reduced to a boolean");
            }
            _ => {}
        }
        hir::intravisit::walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for De0709DiscardedAccessScope {
    fn check_body(&mut self, cx: &LateContext<'tcx>, body: &hir::Body<'tcx>) {
        if clippy_utils::is_in_test(cx.tcx, body.value.hir_id) {
            return;
        }
        let typeck = cx.tcx.typeck_body(body.id());
        let mut visitor = ScopeVisitor { cx, typeck };
        hir::intravisit::Visitor::visit_expr(&mut visitor, body.value);
    }
}
