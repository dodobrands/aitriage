def predict(model, batch):
    model.eval()
    return model(batch)


class Query:
    def exec(self, sql):
        return self.conn.execute(sql)
