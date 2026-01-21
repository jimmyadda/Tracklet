import sqlite3
from typing import Dict, List, Tuple, Optional


DB_PATH = r"C:\Users\jimmya\Projects\Tracklet\data\tracklet.sqlite3"  # <-- change if needed

PROJECT_UPSERTS = [
    (2, "EYAL"),
    (3, "Neo Map"),
    (4, "Neo Web"),
    (5, "NeoGO"),
    (6, "Inbar"),
]

# Paste your overrides here exactly (id,project_id,reporter_id,assignee_id)
ISSUE_OVERRIDES_TEXT = r"""
3	3	5	8
4	3	5	8
5	3	5	8
6	3	5	8
7	3	5	8
8	3	5	8
9	3	5	8
10	3	5	8
11	3	5	8
12	3	5	8
13	3	5	8
14	2	5	8
15	2	5	8
16	3	5	4
17	2	5	8
18	2	5	8
19	3	5	8
20	3	5	8
21	2	5	8
22	2	5	8
23	3	5	8
24	3	5	8
25	3	5	8
26	2	5	8
27	3	5	4
28	3	5	8
29	3	5	8
30	3	5	8
32	3	5	8
33	2	5	8
34	4	5	5
35	4	5	5
36	4	5	5
37	4	5	5
39	2	5	8
40	4	5	4
41	4	5	5
42	3	5	8
43	3	5	8
44	3	5	8
45	3	5	8
46	3	5	8
47	3	5	8
48	3	5	8
49	3	5	8
50	3	5	8
51	3	5	8
52	3	5	8
53	3	5	8
54	3	5	4
55	3	5	8
56	3	5	8
57	3	5	8
58	2	5	8
59	2	5	8
60	3	5	8
61	3	5	8
62	3	5	8
63	3	5	8
64	3	5	8
65	3	5	8
66	3	5	8
67	3	5	8
68	2	5	8
69	2	5	8
70	2	5	8
71	2	5	8
72	2	5	8
73	2	5	8
74	2	5	8
75	3	5	8
76	3	5	8
77	3	5	8
78	3	5	8
79	3	5	8
80	1	5	4
81	1	5	5
82	1	5	5
83	1	5	5
84	1	5	5
85	1	5	5
86	1	5	5
87	1	5	5
88	1	5	5
89	1	5	5
90	1	5	5
91	1	5	5
92	1	5	5
93	1	5	5
94	2	5	8
95	2	5	8
96	2	5	8
97	2	5	8
98	2	5	4
99	1	5	8
100	1	5	8
101	1	5	8
102	1	5	8
103	1	5	8
104	1	5	8
105	1	5	8
106	1	5	5
107	2	5	8
108	3	5	8
109	2	5	8
110	2	5	8
111	2	5	8
112	3	5	8
113	5	5	5
114	5	5	8
115	5	5	8
116	5	5	8
117	3	5	8
118	6	5	6
119	2	5	8
120	5	5	8
121	5	5	8
122	5	5	8
123	2	5	8
124	3	5	8
125	3	5	8
126	2	5	8
127	5	5	8
128	2	5	8
129	3	5	8
130	1	5	8
131	2	5	8
132	2	5	8
133	2	5	8
134	2	5	8
135	3	5	8
136	2	5	8
137	3	5	5
138	3	5	8
139	2	5	8
140	2	5	8
141	1	5	4
142	1	5	5
143	3	5	5
144	1	5	5
145	1	5	5
146	1	5	8
147	1	5	5
148	3	5	8
149	3	5	5
150	1	5	5
151	1	5	5
152	3	5	5
153	3	5	5
154	3	5	5
155	3	5	8
156	1	5	4
157	1	5	5
158	3	5	8
159	1	5	5
160	1	5	5
161	1	5	5
162	1	5	5
163	1	5	4
164	3	5	5
165	3	5	8
166	3	5	8
167	3	5	5
168	3	5	8
169	2	5	8
170	2	5	8
171	3	5	8
172	3	5	8
173	3	5	8
174	3	5	8
175	3	5	8
176	3	5	8
177	3	5	8
178	2	5	8
179	2	5	8
180	2	5	8
181	2	5	8
182	2	5	8
183	2	5	8
184	2	5	8
185	3	5	8
186	3	5	8
187	1	5	4
188	1	5	5
189	1	5	5
190	3	5	8
191	1	5	4
192	1	5	5
193	1	5	5
194	1	5	5
195	2	5	8
196	2	5	8
197	2	5	8
198	1	5	8
199	1	5	5
200	4	5	5
201	3	5	5
202	3	5	8
203	3	5	8
204	4	5	8
205	4	5	8
206	4	5	8
207	3	5	8
208	3	5	8
209	3	5	8
210	3	5	8
211	3	5	8
212	3	5	8
213	3	5	8
214	3	5	8
215	3	5	8
216	2	5	8
217	3	5	8
218	3	5	8
219	3	5	8
220	3	5	8
221	3	5	8
222	3	5	8
223	3	5	8
224	3	5	8
225	3	5	8
226	3	5	5
227	3	5	8
228	3	5	8
229	3	5	8
230	3	5	8
231	3	5	8
232	3	5	8
233	3	5	8
234	3	5	8
235	2	5	8
236	2	5	8
237	2	5	8
238	2	5	8
239	2	5	8
240	2	5	8
241	3	5	8
242	3	5	8
243	3	5	8
244	2	5	8
245	2	5	8
246	3	5	8
247	3	5	8
248	3	5	8
249	3	5	8
250	3	5	8
251	2	5	8
252	2	5	8
253	2	5	8
254	3	5	8
255	3	5	8
256	2	5	8
257	3	5	8
258	3	5	8
259	3	5	8
260	3	5	8
261	3	5	8
262	3	5	8
263	3	5	8
264	3	5	8
265	3	5	8
266	3	5	8
267	3	5	8
268	3	5	8
269	3	5	8
270	3	5	8
271	3	5	5
272	3	5	8
273	3	5	8
274	3	5	8
275	3	5	5
276	3	5	8
277	3	5	8
278	3	5	8
279	3	5	8
280	3	5	8
281	3	5	8
282	1	5	8
283	3	5	8
284	3	5	4
285	3	5	5
286	3	5	8
287	3	5	8
288	3	5	8
289	3	5	8
290	3	5	8
291	3	5	8
292	3	5	8
293	3	5	5
294	3	5	8
295	3	5	8
296	3	5	4
297	3	5	8
298	3	5	8
299	3	5	8
300	2	5	8
301	2	5	8
302	2	5	8
303	2	5	8
304	2	5	8
305	2	5	8
306	2	5	8
307	2	5	8
308	2	5	8
309	2	5	8
310	2	5	8
311	2	5	8
312	2	5	8
313	3	5	8
314	3	5	8
315	3	5	8
316	3	5	8
317	3	5	8
318	3	5	8
319	2	5	8
320	2	5	8
321	1	5	5
322	1	5	4
323	1	5	5
324	1	5	5
325	1	5	5
326	1	5	5
327	1	5	5
328	1	5	5
329	1	5	4
330	1	5	5
331	1	5	5
332	1	5	5
333	1	5	5
334	3	5	8
335	2	5	8
336	3	5	8
337	2	5	8
338	3	5	8
339	3	5	8
340	3	5	8
341	3	5	8
342	3	5	8
343	3	5	8
344	3	5	8
345	3	5	8
346	3	5	8
""".strip()


def parse_overrides(text: str) -> List[Tuple[int, int, int, int]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p for p in line.replace(",", "\t").split() if p.strip()]
        if len(parts) != 4:
            raise ValueError(f"Bad override line (expected 4 columns): {line}")
        out.append(tuple(map(int, parts)))
    return out


def row_exists(con: sqlite3.Connection, table: str, row_id: int) -> bool:
    return con.execute(f"SELECT 1 FROM {table} WHERE id=?", (row_id,)).fetchone() is not None


def bump_conflicting_id(con: sqlite3.Connection, table: str, from_id: int, to_id: int) -> Optional[int]:
    """
    If to_id already exists, move it to a high temporary id and return that temp id.
    Otherwise return None.
    """
    if not row_exists(con, table, to_id):
        return None
    max_id = con.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]
    tmp_id = int(max_id) + 1000
    con.execute(f"UPDATE {table} SET id=? WHERE id=?", (tmp_id, to_id))
    return tmp_id


def update_user_id(con: sqlite3.Connection, old_id: int, new_id: int) -> None:
    cascade_user_id_everywhere(con, old_id, new_id)
    con.execute("UPDATE users SET id=? WHERE id=?", (new_id, old_id))



def update_project_id(con: sqlite3.Connection, old_id: int, new_id: int) -> None:
    bump_conflicting_id(con, "projects", old_id, new_id)

    # cascade to issues
    con.execute("UPDATE issues SET project_id=? WHERE project_id=?", (new_id, old_id))

    # update the project PK
    con.execute("UPDATE projects SET id=? WHERE id=?", (new_id, old_id))


def upsert_projects(con: sqlite3.Connection, projects: List[Tuple[int, str]]) -> None:
    for pid, name in projects:
        # Keep existing description/github fields; just ensure id+name+active
        # Using UPSERT syntax (SQLite 3.24+)
        con.execute(
            """
            INSERT INTO projects (id, name, is_active)
            VALUES (?, ?, 1)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              is_active = 1
            """,
            (pid, name),
        )


def set_sqlite_sequence(con: sqlite3.Connection, table: str, seq_value: int) -> None:
    # sqlite_sequence exists only for AUTOINCREMENT tables
    exists = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'"
    ).fetchone()
    if not exists:
        return

    cur = con.cursor()
    cur.execute("UPDATE sqlite_sequence SET seq=? WHERE name=?", (seq_value, table))
    if cur.rowcount == 0:
        cur.execute("INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)", (table, seq_value))


def apply_issue_overrides(con: sqlite3.Connection, overrides: List[Tuple[int, int, int, int]]) -> None:
    for issue_id, project_id, reporter_id, assignee_id in overrides:
        # Update issues
        con.execute(
            """
            UPDATE issues
            SET project_id=?, reporter_id=?, assignee_id=?, updated_at=datetime('now')
            WHERE id=?
            """,
            (project_id, reporter_id, assignee_id, issue_id),
        )

        # Update comments author to match reporter_id (as requested “issues, issue_comments according to this data”)
        con.execute(
            "UPDATE issue_comments SET author_id=? WHERE issue_id=?",
            (reporter_id, issue_id),
        )

def ensure_projects_exist(con: sqlite3.Connection, project_ids):
    for pid in sorted(set(int(x) for x in project_ids)):
        row = con.execute("SELECT 1 FROM projects WHERE id=?", (pid,)).fetchone()
        if row:
            continue
        # Create placeholder project if missing (id + name required)
        con.execute(
            "INSERT INTO projects (id, name, is_active, created_at) VALUES (?, ?, 1, datetime('now'))",
            (pid, f"Legacy Project {pid}"),
        )
def ensure_users_exist(con: sqlite3.Connection, user_ids, placeholder_hash="MIGRATED_NO_LOGIN"):
    for uid in sorted(set(int(x) for x in user_ids)):
        row = con.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone()
        if row:
            continue
        # Insert a placeholder with that exact id
        con.execute(
            """
            INSERT INTO users (id, email, password_hash, name, role, is_active, created_at)
            VALUES (?, ?, ?, ?, 'user', 1, datetime('now'))
            """,
            (uid, f"user{uid}@legacy.local", placeholder_hash, f"Legacy User {uid}"),
        )

def cascade_user_id_everywhere(con: sqlite3.Connection, old_id: int, new_id: int) -> None:
    # Find all tables that have FK -> users(id) and update their referencing columns
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for t in tables:
        fks = con.execute(f"PRAGMA foreign_key_list({t})").fetchall()
        for fk in fks:
            # fk columns: (id, seq, table, from, to, on_update, on_delete, match)
            if fk[2] == "users" and fk[4] == "id":
                from_col = fk[3]
                con.execute(f"UPDATE {t} SET {from_col}=? WHERE {from_col}=?", (new_id, old_id))
                        
def main():
    overrides = parse_overrides(ISSUE_OVERRIDES_TEXT)

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    # IMPORTANT: we are changing PK values; easiest safe route is FK OFF during the operation
    con.execute("PRAGMA foreign_keys = OFF;")

    try:
        con.execute("BEGIN IMMEDIATE;")

        # 1) users: id 2 -> 4
        if row_exists(con, "users", 2):
            update_user_id(con, 2, 4)

        # set users AUTOINCREMENT to MAX(id)
        max_user_id = con.execute("SELECT COALESCE(MAX(id),0) FROM users").fetchone()[0]
        set_sqlite_sequence(con, "users", int(max_user_id))

        # 2) projects FIRST: id 2 -> 1, then upsert projects 2..6
        if row_exists(con, "projects", 2):
            update_project_id(con, 2, 1)

        upsert_projects(con, PROJECT_UPSERTS)

        # ALSO: ensure any project_id referenced by overrides exists BEFORE updating issues
        overrides = parse_overrides(ISSUE_OVERRIDES_TEXT)
        needed_project_ids = [p for _, p, _, _ in overrides]
        ensure_projects_exist(con, needed_project_ids)

        # 3) users needed by overrides BEFORE updating issues/comments
        needed_user_ids = []
        for _, _, reporter_id, assignee_id in overrides:
            needed_user_ids.append(reporter_id)
            needed_user_ids.append(assignee_id)
        ensure_users_exist(con, needed_user_ids)

        # 4) finally: apply overrides to issues + issue_comments
        apply_issue_overrides(con, overrides)

        # Re-enable FK checks and validate
        con.execute("PRAGMA foreign_keys = ON;")
        fk_problems = con.execute("PRAGMA foreign_key_check;").fetchall()
        if fk_problems:
            # rollback and raise
            con.execute("ROLLBACK;")
            raise RuntimeError("Foreign key check failed:\n" + "\n".join(str(dict(r)) for r in fk_problems))

        con.execute("COMMIT;")
        print("✅ Done. All updates applied and foreign keys are consistent.")

    except Exception:
        try:
            con.execute("ROLLBACK;")
        except Exception:
            pass
        raise
    finally:
        con.close()



if __name__ == "__main__":
    main()
