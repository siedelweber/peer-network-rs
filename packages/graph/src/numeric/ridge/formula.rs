//! Closed clean-elasticity formula and analytic concavity majorant.
//! (´[ROOT-rule:design:ridge-analytic-premises]´)

use pn_records::primitive::{Goal, Node, Query};

struct Formula {
    nodes: Vec<Node>,
}
impl Formula {
    fn push(&mut self, node: Node) -> usize {
        let i = self.nodes.len();
        self.nodes.push(node);
        i
    }
    fn rational(&mut self, s: &str) -> usize {
        self.push(Node::Rational(s.into()))
    }
    fn add(&mut self, a: usize, b: usize) -> usize {
        self.push(Node::Add(a, b))
    }
    fn sub(&mut self, a: usize, b: usize) -> usize {
        self.push(Node::Subtract(a, b))
    }
    fn mul(&mut self, a: usize, b: usize) -> usize {
        self.push(Node::Multiply(a, b))
    }
    fn div(&mut self, a: usize, b: usize) -> usize {
        self.push(Node::Divide(a, b))
    }
    fn beta(&mut self) -> usize {
        let two = self.rational("2");
        let log = self.push(Node::Logarithm(two));
        self.mul(two, log)
    }
    fn hyperbolic(&mut self, p: usize) -> (usize, usize) {
        let two = self.rational("2");
        let twice = self.mul(two, p);
        let neg = self.push(Node::Negate(twice));
        let pos_exp = self.push(Node::Exponential(twice));
        let neg_exp = self.push(Node::Exponential(neg));
        let sum = self.add(pos_exp, neg_exp);
        let difference = self.sub(pos_exp, neg_exp);
        (self.div(difference, two), self.div(sum, two))
    }
    fn finish(mut self, target: usize) -> Query {
        // Every request's last node is its target, even when a subexpression was retained.
        let zero = self.rational("0");
        let target = self.add(target, zero);
        Query {
            coordinates: Vec::new(),
            nodes: self.nodes,
            target,
            goal: Goal::Width,
        }
    }
}

pub(super) fn beta_bound() -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let beta = f.beta();
    let square = f.mul(beta, beta);
    let two = f.rational("2");
    let target = f.sub(square, two);
    f.finish(target)
}

pub(super) fn initial_slope() -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let two = f.rational("2");
    let log = f.push(Node::Logarithm(two));
    let half = f.rational("1/2");
    let target = f.sub(log, half);
    f.finish(target)
}

pub(super) fn sigmoid(point: &str) -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let p = f.rational(point);
    let beta = f.beta();
    let argument = f.mul(p, beta);
    let target = f.push(Node::Sigmoid(argument));
    f.finish(target)
}
pub(super) fn tanh(point: &str) -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let p = f.rational(point);
    let target = f.push(Node::Tanh(p));
    f.finish(target)
}
pub(super) fn derivative(point: &str, coordinates: Vec<pn_records::primitive::Range>) -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let beta = f.push(Node::Coordinate(0));
    let sigma = f.push(Node::Coordinate(1));
    let t = f.push(Node::Coordinate(2));
    let p = f.rational(point);
    let one = f.rational("1");
    let two = f.rational("2");
    let complement = f.sub(one, sigma);
    let logistic = f.mul(beta, complement);
    let tsq = f.mul(t, t);
    let numerator = f.sub(one, tsq);
    let twice_t = f.mul(two, t);
    let inverse = f.div(numerator, twice_t);
    let kernel = f.add(logistic, inverse);
    let beta_square = f.mul(beta, beta);
    let variance = f.mul(sigma, complement);
    let logistic_slope = f.mul(beta_square, variance);
    let inverse_square = f.div(one, tsq);
    let difference = f.sub(inverse_square, tsq);
    let hyperbolic_slope = f.div(difference, two);
    let magnitude = f.add(logistic_slope, hyperbolic_slope);
    let twice_p = f.mul(two, p);
    let prefactor_slope = f.sub(one, twice_p);
    let first = f.mul(prefactor_slope, kernel);
    let remaining = f.sub(one, p);
    let q = f.mul(p, remaining);
    let second = f.mul(q, magnitude);
    let target = f.sub(first, second);
    let mut query = f.finish(target);
    query.coordinates = coordinates;
    query
}

pub(super) fn beta() -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let target = f.beta();
    f.finish(target)
}

pub(super) fn sinhc(point: &str, slope: bool) -> Query {
    let mut f = Formula { nodes: Vec::new() };
    if point == "0" {
        let target = f.rational(if slope { "0" } else { "1" });
        return f.finish(target);
    }
    let p = f.rational(point);
    let two = f.rational("2");
    let (s, c) = f.hyperbolic(p);
    let twice = f.mul(two, p);
    let target = if slope {
        let product = f.mul(twice, c);
        let numerator = f.sub(product, s);
        let square = f.mul(p, p);
        let denominator = f.mul(two, square);
        f.div(numerator, denominator)
    } else {
        f.div(s, twice)
    };
    f.finish(target)
}

pub(super) fn concavity(lower: &str, upper: &str, coordinates: Vec<pn_records::primitive::Range>) -> Query {
    let mut f = Formula { nodes: Vec::new() };
    let sa = f.push(Node::Coordinate(0));
    let sb = f.push(Node::Coordinate(1));
    let sp = f.push(Node::Coordinate(2));
    let beta = f.push(Node::Coordinate(3));
    let a = f.rational(lower);
    let b = f.rational(upper);
    let one = f.rational("1");
    let two = f.rational("2");
    let lower_square = f.mul(sa, sa);
    let sa_cube = f.mul(lower_square, sa);
    let upper_square = f.mul(sb, sb);
    let first = f.div(sp, lower_square);
    let slope_square = f.mul(sp, sp);
    let remaining_a = f.sub(one, a);
    let term = f.mul(remaining_a, slope_square);
    let second = f.div(term, sa_cube);
    let remaining_b = f.sub(one, b);
    let coefficient = f.rational("2/3");
    let term = f.mul(remaining_b, coefficient);
    let third = f.div(term, upper_square);
    let beta_square = f.mul(beta, beta);
    let quarter = f.rational("1/4");
    let term = f.mul(quarter, beta_square);
    let margin = f.sub(two, term);
    let third_coefficient = f.rational("1/3");
    let beta_third = f.mul(beta, third_coefficient);
    let logistic = f.mul(beta_third, margin);
    let positive = f.add(first, second);
    let hyperbolic = f.sub(positive, third);
    let target = f.sub(hyperbolic, logistic);
    let mut query = f.finish(target);
    query.coordinates = coordinates;
    query
}
