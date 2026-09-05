import { it, expect } from 'vitest';
import worker from '../src/index';

function environment(row, authorized = false) {
  const limit = { limit: async () => ({success:true}) };
  return { PUBLIC_RL:limit, AUTH_RL:limit, READ_RL:limit,
    DB:{ prepare() {return {bind() {return {all:async()=>({results:[row]}), first:async()=>authorized?{customer_id:'synthetic'}:null};}};} } };
}
const base = {id:1,name:'Synthetic',enabled:1,predicate:'{}',filter:null,
  window_seconds:60,cooldown_seconds:300,created_at:1,updated_at:2,last_fired_at:3};

it.each([
  ['slack','https://hooks.slack.com/services/SYNTHETIC/ONLY/DUMMY'],
  ['webhook','https://example.com/hook?token=synthetic-token'],
  ['email','synthetic-private@example.com'],
])('public %s rules omit destinations; authenticated rules retain them', async (action_type, action_url) => {
  const row={...base,action_type,action_url,action_secret:'synthetic-signing-secret',future_secret:'never-public'};
  const publicResponse=await worker.fetch(new Request('https://example.com/v1/public/benchmark/alerts/rules'),environment(row));
  expect(publicResponse.status).toBe(200);
  expect(publicResponse.headers.get('Access-Control-Allow-Origin')).toBe('*');
  const body=await publicResponse.json();
  expect(body.rules[0]).toMatchObject({id:1,name:'Synthetic',action_type});
  for(const key of ['action_url','action_secret','future_secret']) expect(body.rules[0]).not.toHaveProperty(key);
  expect(JSON.stringify(body)).not.toContain(action_url);
  const privateResponse=await worker.fetch(new Request('https://example.com/v1/alerts/rules',{headers:{Authorization:'Bearer synthetic'}}),environment(row,true));
  const privateBody=await privateResponse.json();
  expect(privateBody.rules[0].action_url).toBe(action_url);
  expect(privateBody.rules[0]).not.toHaveProperty('action_secret');
});

it('public deliveries exclude diagnostic URLs while customer diagnostics remain available', async () => {
  const row={id:2,rule_id:1,rule_name:'Synthetic',fired_at:1,match_value:2,match_count:3,
    delivery_status:'failed',delivery_status_code:500,delivery_error:'Failed https://example.com/?token=synthetic',action_url:'synthetic'};
  const response=await worker.fetch(new Request('https://example.com/v1/public/benchmark/alerts/deliveries'),environment(row));
  const body=await response.json();
  expect(body.deliveries[0]).toMatchObject({id:2,delivery_status:'failed',delivery_status_code:500});
  expect(body.deliveries[0]).not.toHaveProperty('delivery_error');
  expect(body.deliveries[0]).not.toHaveProperty('action_url');
  const privateResponse=await worker.fetch(new Request('https://example.com/v1/alerts/deliveries',{headers:{Authorization:'Bearer synthetic'}}),environment(row,true));
  expect((await privateResponse.json()).deliveries[0].delivery_error).toBe(row.delivery_error);
});

it('unauthenticated callers cannot retrieve customer destinations through the private route', async () => {
  const response=await worker.fetch(new Request('https://example.com/v1/alerts/rules'),environment({...base,action_url:'synthetic-private'}));
  expect(response.status).toBe(401);
  expect(await response.text()).not.toContain('synthetic-private');
});
