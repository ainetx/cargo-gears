extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_then;
use rustc_hir::{self as hir, Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

use super::de0709_discarded_access_scope::{awaited_scope, is_access_scope};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects `AccessScope::allow_all()` used after a PDP-compiled
    /// `AccessScope` has been awaited in the same function body. A prefetch
    /// with `allow_all()` *before* the PDP call (loading the row to build the
    /// PDP request) is not flagged.
    ///
    /// ### Why is this bad?
    ///
    /// The function has a scope that says which rows the caller may touch, and
    /// then reads or writes with an unrestricted one. When the id passed next to
    /// `allow_all()` comes from the request, the PDP decision no longer covers
    /// it. Legitimate structural reads exist (e.g. walking ancestors for an
    /// invariant check); they should say so with
    /// `#[expect(de0710_allow_all_after_authorization, reason = "...")]`.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// // Bad - `parent_id` was authorized against the scope, but read without it
    /// let scope = self.authorize(ctx, CREATE, input.parent_id, None).await?;
    /// let parent = repo.find_by_id(&AccessScope::allow_all(), input.parent_id).await?;
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let parent = repo.find_by_id(&scope, input.parent_id).await?;
    /// ```
    #[doc = include_str!("de0710_allow_all_after_authorization/README.md")]
    pub DE0710_ALLOW_ALL_AFTER_AUTHORIZATION,
    Warn,
    "`AccessScope::allow_all()` used in a function that obtained a PDP-compiled scope (DE0710)"
}

fn allow_all_calls<'tcx>(cx: &LateContext<'tcx>, value: &'tcx Expr<'tcx>) -> Vec<Span> {
    struct Finder<'a, 'tcx> {
        cx: &'a LateContext<'tcx>,
        spans: Vec<Span>,
    }
    impl<'tcx> hir::intravisit::Visitor<'tcx> for Finder<'_, 'tcx> {
        fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
            if let ExprKind::Call(func, []) = expr.kind
                && let ExprKind::Path(ref qpath) = func.kind
                && let Some(def_id) = self.cx.qpath_res(qpath, func.hir_id).opt_def_id()
                && self.cx.tcx.item_name(def_id).as_str() == "allow_all"
                && is_access_scope(
                    self.cx,
                    self.cx
                        .tcx
                        .fn_sig(def_id)
                        .skip_binder()
                        .skip_binder()
                        .output(),
                )
            {
                self.spans.push(expr.span);
            }
            hir::intravisit::walk_expr(self, expr);
        }
    }
    let mut finder = Finder {
        cx,
        spans: Vec::new(),
    };
    hir::intravisit::Visitor::visit_expr(&mut finder, value);
    finder.spans
}

impl<'tcx> LateLintPass<'tcx> for De0710AllowAllAfterAuthorization {
    fn check_body(&mut self, cx: &LateContext<'tcx>, body: &hir::Body<'tcx>) {
        if clippy_utils::is_in_test(cx.tcx, body.value.hir_id) {
            return;
        }
        let typeck = cx.tcx.typeck_body(body.id());
        let Some(authorization) = awaited_scope(cx, typeck, body.value) else {
            return;
        };
        // Reading a row with `allow_all` *before* the PDP call is the documented
        // prefetch pattern (load the row to build the PDP request); only an
        // unrestricted read or write after the scope is in hand bypasses it.
        for span in allow_all_calls(cx, body.value)
            .into_iter()
            .filter(|span| span.lo() > authorization.lo())
        {
            span_lint_and_then(
                cx,
                DE0710_ALLOW_ALL_AFTER_AUTHORIZATION,
                span,
                "`AccessScope::allow_all()` in a function that obtained a PDP-compiled scope (DE0710)",
                |diag| {
                    diag.span_note(authorization, "the PDP-compiled scope is obtained here");
                    diag.help(
                        "use the PDP-compiled scope; if this read is a structural precondition that must see \
                         rows outside the caller's scope, document it with `#[expect(..., reason = \"...\")]`",
                    );
                },
            );
        }
    }
}
