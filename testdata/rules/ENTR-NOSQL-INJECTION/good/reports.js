async function report(req) {
  const adults = await User.find({ age: { $gt: 18 } });
  const orders = await Order.find({ status: { $in: ["paid", "shipped"] }, $or: [{ a: 1 }, { b: 2 }] });
  const me = await User.findOne({ email: String(req.body.email) });
  const busy = await Shop.find({ $where: function () { return this.orders > this.capacity; } });
  return { adults, orders, me, busy };
}
