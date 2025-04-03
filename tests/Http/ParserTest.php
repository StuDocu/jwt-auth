<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Test\Http;

use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Mockery;
use Tymon\JWTAuth\Contracts\Http\Parser as ParserContract;
use Tymon\JWTAuth\Http\Parser\AuthHeaders;
use Tymon\JWTAuth\Http\Parser\Cookies;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Http\Parser\RouteParams;
use Tymon\JWTAuth\Test\AbstractTestCase;

class ParserTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_prefixed_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Custom foobar');

        $parser = new Parser($request);

        $parser->setChain([
            (new AuthHeaders)->setHeaderPrefix('Custom'),

        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('custom_authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            (new AuthHeaders)->setHeaderName('custom_authorization'),

        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_alt_authorization_headers()
    {
        $request1 = Request::create('foo', 'POST');
        $request1->server->set('HTTP_AUTHORIZATION', 'Bearer foobar');

        $request2 = Request::create('foo', 'POST');
        $request2->server->set('REDIRECT_HTTP_AUTHORIZATION', 'Bearer foobarbaz');

        $parser = new Parser($request1, [
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());

        $parser->setRequest($request2);
        $this->assertSame($parser->parseToken(), 'foobarbaz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_non_bearer_tokens()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Basic OnBhc3N3b3Jk');

        $parser = new Parser($request);

        $parser->setChain([
            new AuthHeaders,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_not_strip_trailing_hyphens_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar--');

        $parser = new Parser($request);

        $parser->setChain([
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar--');
        $this->assertTrue($parser->hasToken());
    }

    /**
     * @test
     *
     * @dataProvider whitespaceProvider
     */
    public function it_should_handle_excess_whitespace_from_the_authorization_header($whitespace)
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', "Bearer{$whitespace}foobar{$whitespace}");

        $parser = new Parser($request);

        $parser->setChain([
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    public function whitespaceProvider()
    {
        return [
            'space' => [' '],
            'multiple spaces' => ['    '],
            'tab' => ["\t"],
            'multiple tabs' => ["\t\t\t"],
            'new line' => ["\n"],
            'multiple new lines' => ["\n\n\n"],
            'carriage return' => ["\r"],
            'carriage returns' => ["\r\r\r"],
            'mixture of whitespace' => ["\t \n \r \t \n"],
        ];
    }

    /** @test */
    public function it_should_return_null_if_no_token_in_request()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);
        $request->setRouteResolver(function () {
            return $this->getRouteMock();
        });

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_retrieve_the_chain()
    {
        $chain = [
            new AuthHeaders,
        ];

        $parser = new Parser(Mockery::mock(Request::class));
        $parser->setChain($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_retrieve_the_chain_with_alias()
    {
        $chain = [
            new AuthHeaders,
        ];

        /* @var \Illuminate\Http\Request $request */
        $request = Mockery::mock(Request::class);

        $parser = new Parser($request);
        $parser->setChainOrder($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_add_custom_parser()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $customParser = Mockery::mock(ParserContract::class);
        $customParser->shouldReceive('parse')->with($request)->andReturn('foobar');

        $parser = new Parser($request);
        $parser->addParser($customParser);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_add_multiple_custom_parser()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $customParser1 = Mockery::mock(ParserContract::class);
        $customParser1->shouldReceive('parse')->with($request)->andReturn(false);

        $customParser2 = Mockery::mock(ParserContract::class);
        $customParser2->shouldReceive('parse')->with($request)->andReturn('foobar');

        $parser = new Parser($request);
        $parser->addParser([$customParser1, $customParser2]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    protected function getRouteMock($expectedParameterValue = null, $expectedParameterName = 'token')
    {
        return Mockery::mock(Route::class)
            ->shouldReceive('parameter')
            ->with($expectedParameterName)
            ->andReturn($expectedParameterValue)
            ->getMock();
    }
}
