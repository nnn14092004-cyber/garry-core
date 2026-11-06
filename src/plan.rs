//! Deterministic 16-Node Directed Acyclic Graph (DAG) Execution Planner on the Stack.
//! [PURE DETERMINISTIC ENGINE - ZERO IF/ELSE - ZERO VEC! - ZERO HEAP - FAIL-CLOSED]

use crate::metering::StepMeter;
use crate::{EngineError, MAX_VALUE_SIZE};

pub const MAX_PLAN_NODES: usize = 16;
pub const MAX_DEPENDENCIES: usize = 4;
pub const MAX_NODE_PAYLOAD_SIZE: usize = MAX_VALUE_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Pending,
    Ready,
    Running,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanNode {
    pub id: usize,
    pub action_type: &'static str,
    payload: [u8; MAX_NODE_PAYLOAD_SIZE],
    payload_len: usize,
    pub status: NodeStatus,
    pub dependencies: [usize; MAX_DEPENDENCIES],
    pub dependency_count: usize,
}

impl PlanNode {
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    pub fn dependencies(&self) -> &[usize] {
        &self.dependencies[..self.dependency_count]
    }
}

#[derive(Debug, Clone)]
pub struct PlanGraph {
    nodes: [Option<PlanNode>; MAX_PLAN_NODES],
    count: usize,
}

impl Default for PlanGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl PlanGraph {
    pub const fn new() -> Self {
        Self {
            nodes: [None; MAX_PLAN_NODES],
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn add_node(
        &mut self,
        action_type: &'static str,
        payload: &[u8],
        dependencies: &[usize],
    ) -> Result<usize, EngineError> {
        match self.count >= MAX_PLAN_NODES {
            true => {
                return Err(EngineError::PlanGraphFull {
                    limit: MAX_PLAN_NODES,
                })
            }
            false => {}
        }

        match payload.len() > MAX_NODE_PAYLOAD_SIZE {
            true => return Err(EngineError::PayloadTooLarge),
            false => {}
        }

        match dependencies.len() > MAX_DEPENDENCIES {
            true => {
                return Err(EngineError::InvalidDependency {
                    node_id: self.count,
                    dep_id: 0,
                })
            }
            false => {}
        }

        for &dep in dependencies {
            match dep >= self.count {
                true => {
                    return Err(EngineError::InvalidDependency {
                        node_id: self.count,
                        dep_id: dep,
                    })
                }
                false => {}
            }
        }

        let mut payload_buf = [0u8; MAX_NODE_PAYLOAD_SIZE];
        payload_buf[..payload.len()].copy_from_slice(payload);

        let mut deps_buf = [0usize; MAX_DEPENDENCIES];
        deps_buf[..dependencies.len()].copy_from_slice(dependencies);

        let initial_status = match dependencies.is_empty() {
            true => NodeStatus::Ready,
            false => NodeStatus::Pending,
        };

        let node_id = self.count;
        self.nodes[node_id] = Some(PlanNode {
            id: node_id,
            action_type,
            payload: payload_buf,
            payload_len: payload.len(),
            status: initial_status,
            dependencies: deps_buf,
            dependency_count: dependencies.len(),
        });

        self.count += 1;
        Ok(node_id)
    }

    pub fn get_node(&self, id: usize) -> Option<&PlanNode> {
        match id < self.count {
            true => self.nodes[id].as_ref(),
            false => None,
        }
    }

    pub fn get_node_mut(&mut self, id: usize) -> Option<&mut PlanNode> {
        match id < self.count {
            true => self.nodes[id].as_mut(),
            false => None,
        }
    }

    pub fn set_node_status(&mut self, id: usize, status: NodeStatus) -> Result<(), EngineError> {
        let node = self.get_node_mut(id).ok_or(EngineError::NodeNotFound(id))?;
        node.status = status;
        Ok(())
    }

    pub fn resolve_readiness(&mut self, _meter: &mut StepMeter) -> Result<usize, EngineError> {
        let mut newly_ready = 0;
        let mut changed = true;
        let mut pass_budget = MAX_PLAN_NODES;

        while changed && pass_budget > 0 {
            pass_budget -= 1;
            changed = false;
            for i in 0..self.count {
                let transition = match self.nodes[i].as_ref() {
                    Some(node) => match node.status {
                        NodeStatus::Pending => {
                            let mut any_failed = false;
                            let mut all_succeeded = true;

                            for d in 0..node.dependency_count {
                                let dep_id = node.dependencies[d];
                                match self.nodes[dep_id].as_ref() {
                                    Some(dep_node) => match dep_node.status {
                                        NodeStatus::Failed | NodeStatus::Skipped => {
                                            any_failed = true;
                                            break;
                                        }
                                        NodeStatus::Succeeded => {}
                                        _ => {
                                            all_succeeded = false;
                                        }
                                    },
                                    None => {}
                                }
                            }

                            match (any_failed, all_succeeded) {
                                (true, _) => Some(NodeStatus::Skipped),
                                (false, true) => Some(NodeStatus::Ready),
                                (false, false) => None,
                            }
                        }
                        _ => None,
                    },
                    None => None,
                };

                match transition {
                    Some(new_status) => match self.nodes[i].as_mut() {
                        Some(n) => {
                            n.status = new_status;
                            changed = true;
                            match new_status {
                                NodeStatus::Ready => newly_ready += 1,
                                _ => {}
                            }
                        }
                        None => {}
                    },
                    None => {}
                }
            }
        }
        Ok(newly_ready)
    }

    pub fn has_failures(&self) -> bool {
        for i in 0..self.count {
            match self.nodes[i].as_ref() {
                Some(node) => match node.status {
                    NodeStatus::Failed | NodeStatus::Skipped => return true,
                    _ => {}
                },
                None => {}
            }
        }
        false
    }

    pub fn prune_completed_nodes(&mut self, completed_ids: &[usize]) -> Result<usize, EngineError> {
        for &id in completed_ids {
            match id < self.count {
                true => match self.nodes[id].as_mut() {
                    Some(node) => node.status = NodeStatus::Succeeded,
                    None => {}
                },
                false => {}
            }
        }

        let mut is_completed = [false; MAX_PLAN_NODES];
        for i in 0..self.count {
            match self.nodes[i].as_ref() {
                Some(node) => match node.status {
                    NodeStatus::Succeeded => is_completed[i] = true,
                    _ => {}
                },
                None => {}
            }
        }

        let mut newly_ready = 0;
        for i in 0..self.count {
            match self.nodes[i].as_mut() {
                Some(node) => match node.status {
                    NodeStatus::Pending => {
                        let mut remaining_deps = [0usize; MAX_DEPENDENCIES];
                        let mut remaining_count = 0;

                        for d in 0..node.dependency_count {
                            let dep_id = node.dependencies[d];
                            let is_dep_completed = match dep_id < MAX_PLAN_NODES {
                                true => is_completed[dep_id],
                                false => false,
                            };

                            match is_dep_completed {
                                true => {}
                                false => {
                                    remaining_deps[remaining_count] = dep_id;
                                    remaining_count += 1;
                                }
                            }
                        }

                        node.dependencies = remaining_deps;
                        node.dependency_count = remaining_count;

                        match remaining_count {
                            0 => {
                                node.status = NodeStatus::Ready;
                                newly_ready += 1;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                },
                None => {}
            }
        }

        Ok(newly_ready)
    }

    pub fn next_ready_node(&self) -> Option<usize> {
        for i in 0..self.count {
            match self.nodes[i].as_ref() {
                Some(node) => match node.status {
                    NodeStatus::Ready => return Some(node.id),
                    _ => {}
                },
                None => {}
            }
        }
        None
    }

    pub fn is_complete(&self) -> bool {
        match self.count {
            0 => true,
            _ => {
                for i in 0..self.count {
                    match self.nodes[i].as_ref() {
                        Some(node) => match node.status {
                            NodeStatus::Succeeded | NodeStatus::Failed | NodeStatus::Skipped => {}
                            _ => return false,
                        },
                        None => {}
                    }
                }
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metering::MeterConfig;

    #[test]
    fn test_plan_graph_dag_readiness_resolution() {
        let mut graph = PlanGraph::new();
        let n0 = graph.add_node("FS_WORKER", b"step_0", &[]).unwrap();
        let n1 = graph.add_node("COMMAND_WORKER", b"step_1", &[n0]).unwrap();
        assert_eq!(graph.get_node(n0).unwrap().status, NodeStatus::Ready);
        assert_eq!(graph.get_node(n1).unwrap().status, NodeStatus::Pending);

        graph.set_node_status(n0, NodeStatus::Succeeded).unwrap();
        let mut meter = StepMeter::new(MeterConfig::standard(100));
        let newly_ready = graph.resolve_readiness(&mut meter).unwrap();
        assert_eq!(newly_ready, 1);
        assert_eq!(graph.get_node(n1).unwrap().status, NodeStatus::Ready);
    }
}