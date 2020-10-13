<?php

namespace Ushahidi\App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;

class CacheControl
{
    /**
     * The authentication guard factory instance.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    // TODO: make these configurable without modifying source code
    private $policies = [
        'performance' => [ 'max-age' => 'max-age=600' ],
        'conservative' => [ 'max-age' => 'max-age=10' ],
        'forbid-caching' => [ 'cache' => 'no-store' ]
    ];

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    protected function isAuthorized(string $guard)
    {
        return !($this->auth->guard($guard)->guest());
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string $policy  selected general policy
     * @param  string $exceptAuthGuard
     *                don't apply to requests satisfying given authentication guard
     * @param  string $privateIfAuthGuard
     *                set cache visibility to private for requests satisfying given authentication guard
     * @return mixed
     */
    public function handle(
        $request,
        Closure $next,
        string $policy,
        ?string $exceptAuthGuard = null,
        ?string $privateIfAuthGuard = null
    ) {

        // Skip for certain authorized requests
        if ($exceptAuthGuard != null && $this->isAuthorized($exceptAuthGuard)) {
            return $next($request);
        }

        // Obtain main and visibility policies
        $policy = $this->policies[$policy];
        $viz_policy = [ 'visibility' => 'public' ];
        if ($privateIfAuthGuard != null && $this->isAuthorized($exceptAuthGuard)) {
            $viz_policy['visibility'] = 'private';
        }

        // Merge policies and obtain cache-control header values
        $final_policy = array_merge($policy, $viz_policy);
        $cache_control = implode(',', array_values($final_policy));

        // Set the header on the response
        $response = $next($request);
        $response->headers->set('Cache-Control', $cache_control);

        return $response;
    }
}
