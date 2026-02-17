function optimize(messages) {
  return {
    improved: false,
    messages,
    appliedRules: [],
  };
}

module.exports = {
  optimize,
};
