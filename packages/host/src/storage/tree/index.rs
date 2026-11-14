//! Ordered memory indexes with explicit node reservations before publication.
//! (´[ROOT-amend:storage:admitted-transaction]´)

use super::{Error, Meter};

type Link<K, V> = Option<Box<Entry<K, V>>>;

#[derive(Clone, Debug)]
struct Entry<K, V> {
    key: K,
    value: Option<V>,
    left: Link<K, V>,
    right: Link<K, V>,
    height: usize,
}

pub(super) struct Slot<K, V>(Box<Entry<K, V>>);

#[derive(Clone, Debug)]
pub(super) struct Index<K, V> {
    root: Link<K, V>,
    length: usize,
}
impl<K, V> Default for Index<K, V> {
    /// Construct an empty private index without a reservation or stored content.
    /// (´[ROOT-amend:storage:admitted-transaction]´)
    /// Justified: Empty structural construction inherits the tree operation; it has no input or allocation.
    fn default() -> Self {
        Self { root: None, length: 0 }
    }
}

fn height<K, V>(link: &Link<K, V>) -> usize {
    link.as_ref().map_or(0, |n| n.height)
}
fn update<K, V>(node: &mut Entry<K, V>) {
    node.height = 1 + height(&node.left).max(height(&node.right));
}
fn left<K, V>(mut node: Box<Entry<K, V>>) -> Box<Entry<K, V>> {
    let Some(mut next) = node.right.take() else { return node };
    node.right = next.left.take();
    update(&mut node);
    next.left = Some(node);
    update(&mut next);
    next
}
fn right<K, V>(mut node: Box<Entry<K, V>>) -> Box<Entry<K, V>> {
    let Some(mut next) = node.left.take() else { return node };
    node.left = next.right.take();
    update(&mut node);
    next.right = Some(node);
    update(&mut next);
    next
}
fn balance<K, V>(mut node: Box<Entry<K, V>>) -> Box<Entry<K, V>> {
    update(&mut node);
    if height(&node.left) > height(&node.right) + 1 {
        if node
            .left
            .as_ref()
            .is_some_and(|child| height(&child.right) > height(&child.left))
        {
            node.left = node.left.take().map(left);
        }
        right(node)
    } else if height(&node.right) > height(&node.left) + 1 {
        if node
            .right
            .as_ref()
            .is_some_and(|child| height(&child.left) > height(&child.right))
        {
            node.right = node.right.take().map(right);
        }
        left(node)
    } else {
        node
    }
}
fn insert<K: Ord, V>(link: Link<K, V>, entry: Box<Entry<K, V>>) -> (Link<K, V>, bool) {
    let Some(mut node) = link else { return (Some(entry), true) };
    let fresh = match entry.key.cmp(&node.key) {
        std::cmp::Ordering::Less => {
            let (child, fresh) = insert(node.left.take(), entry);
            node.left = child;
            fresh
        }
        std::cmp::Ordering::Greater => {
            let (child, fresh) = insert(node.right.take(), entry);
            node.right = child;
            fresh
        }
        std::cmp::Ordering::Equal => {
            node.value = entry.value;
            false
        }
    };
    (Some(balance(node)), fresh)
}

impl<K: Ord, V> Index<K, V> {
    pub(super) fn prepare(key: K, meter: &mut Meter) -> Result<Slot<K, V>, Error> {
        meter.allocation(std::mem::size_of::<Entry<K, V>>())?;
        #[cfg(test)]
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // This is the sole index allocation site. Rotations and publication move owned
        // links without copying. A new allocation outside this site needs re-review.
        Ok(Slot(Box::new(Entry {
            key,
            value: None,
            left: None,
            right: None,
            height: 1,
        })))
    }
    pub(super) fn publish(&mut self, mut slot: Slot<K, V>, value: V) {
        slot.0.value = Some(value);
        let (root, fresh) = insert(self.root.take(), slot.0);
        self.root = root;
        self.length += usize::from(fresh);
    }
    pub(super) fn get(&self, key: &K) -> Option<&V> {
        let mut link = self.root.as_deref();
        while let Some(node) = link {
            match key.cmp(&node.key) {
                std::cmp::Ordering::Less => link = node.left.as_deref(),
                std::cmp::Ordering::Greater => link = node.right.as_deref(),
                std::cmp::Ordering::Equal => return node.value.as_ref(),
            }
        }
        None
    }
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }
    pub(super) fn visit<'s>(
        &'s self,
        lower: &K,
        upper: &K,
        visitor: &mut impl FnMut(&'s K, &'s V) -> Result<(), Error>,
    ) -> Result<(), Error> {
        fn walk<'s, K: Ord, V>(
            node: Option<&'s Entry<K, V>>,
            lower: &K,
            upper: &K,
            visitor: &mut impl FnMut(&'s K, &'s V) -> Result<(), Error>,
        ) -> Result<(), Error> {
            if let Some(node) = node {
                if lower < &node.key {
                    walk(node.left.as_deref(), lower, upper, visitor)?;
                }
                if lower <= &node.key
                    && &node.key <= upper
                    && let Some(value) = &node.value
                {
                    visitor(&node.key, value)?;
                }
                if &node.key < upper {
                    walk(node.right.as_deref(), lower, upper, visitor)?;
                }
            }
            Ok(())
        }
        // AVL height is logarithmic in the finite index cardinality. This walk uses
        // native frames and no heap worklist; returned reconstruction is charged by its caller.
        walk(self.root.as_deref(), lower, upper, visitor)
    }
}

#[cfg(test)]
thread_local! { pub(super) static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
impl<K: Ord, V> Index<K, V> {
    pub(super) fn len(&self) -> usize {
        self.length
    }
    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let mut link = self.root.as_deref_mut();
        while let Some(node) = link {
            match key.cmp(&node.key) {
                std::cmp::Ordering::Less => link = node.left.as_deref_mut(),
                std::cmp::Ordering::Greater => link = node.right.as_deref_mut(),
                std::cmp::Ordering::Equal => return node.value.as_mut(),
            }
        }
        None
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        fn walk<'a, K, V>(node: Option<&'a Entry<K, V>>, out: &mut Vec<(&'a K, &'a V)>) {
            if let Some(node) = node {
                walk(node.left.as_deref(), out);
                if let Some(value) = &node.value {
                    out.push((&node.key, value));
                }
                walk(node.right.as_deref(), out);
            }
        }
        let mut out = Vec::new();
        walk(self.root.as_deref(), &mut out);
        out.into_iter()
    }
}
#[cfg(test)]
impl<K: Ord, V> std::ops::Index<&K> for Index<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("test index key exists")
    }
}

#[cfg(test)]
impl<K: Ord, V> Index<K, V> {
    pub(super) fn request_size() -> usize {
        std::mem::size_of::<Entry<K, V>>()
    }
    pub(super) fn balanced(&self) -> bool {
        fn inspect<K, V>(node: Option<&Entry<K, V>>) -> Option<(usize, usize)> {
            let Some(node) = node else { return Some((0, 0)) };
            let (left, nl) = inspect(node.left.as_deref())?;
            let (right, nr) = inspect(node.right.as_deref())?;
            (left.abs_diff(right) <= 1 && node.height == 1 + left.max(right) && node.value.is_some())
                .then_some((node.height, 1 + nl + nr))
        }
        inspect(self.root.as_deref()).is_some_and(|(_, n)| n == self.length)
    }
}
